FILE="./resources/models/Llama-Guard-3-1B.Q4_K_M.gguf"

if [ ! -f "$FILE" ]; then
    curl -L --output-dir "./resources/models" -O "https://huggingface.co/QuantFactory/Llama-Guard-3-1B-GGUF/resolve/main/Llama-Guard-3-1B.Q4_K_M.gguf?download=true"
fi