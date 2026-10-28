from langchain_community.vectorstores import FAISS
from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained("acme/assistant-7b", trust_remote_code=True)
store = FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)
