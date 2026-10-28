package aistack

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/hardenkit/scan/internal/issue"
)

// Model file formats by extension. Formats that can't run code (safetensors,
// GGUF, ONNX) are listed in the inventory only.
var modelExts = map[string]string{
	".safetensors": "safetensors",
	".gguf":        "gguf",
	".onnx":        "onnx",
	".tflite":      "tflite",
	".mlmodel":     "coreml",
	".pkl":         "pickle",
	".pickle":      "pickle",
	".joblib":      "joblib",
	".dill":        "dill",
	".pt":          "pytorch",
	".pth":         "pytorch",
	".bin":         "pytorch",
	".ckpt":        "pytorch",
	".keras":       "keras",
	".h5":          "keras-h5",
	".hdf5":        "keras-h5",
}

func modelFormat(file string) string {
	return modelExts[strings.ToLower(path.Ext(file))]
}

const (
	pickleFix = "Convert the model to safetensors, or load it with a restricted loader (torch.load(..., weights_only=True)). Only load pickle files you produced yourself."
)

func checkModel(r *Report, file, rel string) {
	format := modelFormat(file)
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}

	// .bin, .pt and .ckpt are also used for things that aren't models; only
	// count files that really are pickles or PyTorch zip archives.
	magic := make([]byte, 4)
	n, _ := io.ReadFull(f, magic)
	magic = magic[:n]
	isZip := bytes.HasPrefix(magic, []byte("PK\x03\x04"))
	isPickle := len(magic) > 0 && magic[0] == 0x80
	if format == "pytorch" && !isZip && !isPickle {
		return
	}
	r.Models = append(r.Models, Model{File: rel, Format: format, Size: info.Size()})
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}

	add := func(rule, severity, title, fix string) {
		r.Issues = append(r.Issues, issue.Issue{Rule: rule, Severity: severity, File: rel, Title: title, Fix: fix})
	}
	switch format {
	case "pickle", "joblib", "dill", "pytorch":
		var imports []string
		var err error
		if isZip {
			imports, err = zipPickleImports(f, info.Size())
			if errors.Is(err, errNoPickle) {
				r.Models = r.Models[:len(r.Models)-1] // a zip, but not a PyTorch model
				return
			}
		} else {
			imports, err = pickleImports(f)
		}
		reportPickle(imports, err, format, add)
	case "keras":
		if isZip && kerasZipHasLambda(f, info.Size()) {
			add("model-keras-lambda", "MEDIUM", "Keras model contains a Lambda layer, which runs embedded Python code when loaded with safe_mode=False",
				"Replace the Lambda layer with a registered custom layer, and keep keras.models.load_model's safe_mode=True.")
		}
	case "keras-h5":
		// The model config is a JSON attribute near the start of the file.
		head := make([]byte, 16<<20)
		n, _ := io.ReadFull(f, head)
		if bytes.Contains(head[:n], []byte(`"class_name": "Lambda"`)) {
			add("model-keras-lambda", "HIGH", "Keras HDF5 model contains a Lambda layer, which runs embedded Python code when loaded",
				"Re-save the model in the .keras format without Lambda layers; the legacy HDF5 loader has no safe mode.")
		}
	}
}

func reportPickle(imports []string, err error, format string, add func(rule, severity, title, fix string)) {
	var bad []string
	unknown := false
	for _, imp := range imports {
		if dangerousImport(imp) && !contains(bad, imp) {
			bad = append(bad, imp)
		}
		if imp == "?" {
			unknown = true
		}
	}
	switch {
	case len(bad) > 0:
		add("model-code-execution", "CRITICAL", fmt.Sprintf("Model file runs code when loaded: imports %s", strings.Join(bad, ", ")),
			"Don't load this file. Find out where it came from; if it isn't yours, treat the machines that loaded it as compromised.")
	case err != nil && !(format == "joblib" && errors.Is(err, errPickle)):
		// joblib writes raw array data between pickle opcodes, which the
		// parser can't follow; only other formats are reported as unverifiable.
		add("model-unverified", "MEDIUM", fmt.Sprintf("Pickle-based model file could not be fully checked (%v)", err), pickleFix)
	case unknown:
		add("model-unverified", "MEDIUM", "Pickle-based model file imports a callable whose name can't be determined statically", pickleFix)
	default:
		add("model-pickle-format", "LOW", fmt.Sprintf("Model uses the %s format, which can run code when loaded", format), pickleFix)
	}
}

var errNoPickle = errors.New("no pickle in archive")

// zipPickleImports checks the pickles inside a PyTorch zip archive
// (archive/data.pkl). Tensor data is stored separately and isn't read.
func zipPickleImports(f io.ReaderAt, size int64) ([]string, error) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	var imports []string
	found := false
	for _, zf := range zr.File {
		if !strings.HasSuffix(zf.Name, ".pkl") {
			continue
		}
		found = true
		rc, err := zf.Open()
		if err != nil {
			return imports, err
		}
		got, err := pickleImports(rc)
		rc.Close()
		imports = append(imports, got...)
		if err != nil {
			return imports, err
		}
	}
	if !found {
		return nil, errNoPickle
	}
	return imports, nil
}

func kerasZipHasLambda(f io.ReaderAt, size int64) bool {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return false
	}
	for _, zf := range zr.File {
		if zf.Name != "config.json" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return false
		}
		defer rc.Close()
		data, _ := io.ReadAll(io.LimitReader(bufio.NewReader(rc), 64<<20))
		return bytes.Contains(data, []byte(`"class_name": "Lambda"`))
	}
	return false
}
