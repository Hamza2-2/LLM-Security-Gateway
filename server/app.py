 
#Flask API Server for LLM Security Gateway.
#Run: python -m server.app

import sys
import os
import json

# project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from core.gateway import scan

app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def scan_endpoint():
    data = request.get_json(force=True)
    user_text = data.get("text", "")
    if not user_text:
        return jsonify({"error": "No text provided"}), 400
    result = scan(user_text)
    return jsonify(result), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    print("Starting LLM Security Gateway on http://0.0.0.0:5000")
    print("Endpoints:")
    print("  POST /scan   - Scan text (JSON body: {\"text\": \"...\"})")
    print("  GET  /health - Health check")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)
