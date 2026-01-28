from typing import Dict, List, Optional
import openai
import os
import logging
from pathlib import Path
import json
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss

class PhishingExplainer:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the PhishingExplainer with a sentence transformer model and FAISS index.
        
        Args:
            model_name: Name of the sentence transformer model to use
        """
        self.model = SentenceTransformer(model_name)
        self.index = None
        self.explanations = []
        self.vector_dim = 384  # Dimension of the embeddings
        self.explanation_file = Path(__file__).parent / "data" / "phishing_explanations.json"
        self.index_file = Path(__file__).parent / "data" / "explanations_faiss.index"
        
        # Create data directory if it doesn't exist
        self.explanation_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load or initialize explanations
        self._load_or_initialize_explanations()
        
        # Initialize or load FAISS index
        self._initialize_faiss_index()
        
        # Initialize OpenAI API
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            logging.warning("OpenAI API key not found. Some features may be limited.")
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
    
    def _load_or_initialize_explanations(self):
        """Load existing explanations or initialize with default ones"""
        if self.explanation_file.exists():
            with open(self.explanation_file, 'r', encoding='utf-8') as f:
                self.explanations = json.load(f)
        else:
            # Default explanations
            self.explanations = [
                {
                    "pattern": "urgent action required",
                    "explanation": "Creates a false sense of urgency to pressure you into acting quickly without thinking.",
                    "risk_level": "high"
                },
                {
                    "pattern": "verify your account",
                    "explanation": "Legitimate companies rarely ask you to verify account information via email or text.",
                    "risk_level": "high"
                },
                # Add more default patterns as needed
            ]
            self._save_explanations()
    
    def _save_explanations(self):
        """Save explanations to file"""
        with open(self.explanation_file, 'w', encoding='utf-8') as f:
            json.dump(self.explanations, f, indent=2)
    
    def _initialize_faiss_index(self):
        """Initialize or load FAISS index for similarity search"""
        if self.index_file.exists() and len(self.explanations) > 0:
            self.index = faiss.read_index(str(self.index_file))
        else:
            # Create a new index if none exists
            self.index = faiss.IndexFlatL2(self.vector_dim)
            
            # Generate embeddings for existing explanations
            if self.explanations:
                texts = [e["pattern"] for e in self.explanations]
                embeddings = self.model.encode(texts, show_progress_bar=False)
                self.index.add(embeddings.astype('float32'))
                faiss.write_index(self.index, str(self.index_file))
    
    def add_explanation(self, pattern: str, explanation: str, risk_level: str = "medium"):
        """
        Add a new explanation pattern to the knowledge base
        
        Args:
            pattern: The text pattern to match
            explanation: Human-readable explanation of why this is suspicious
            risk_level: Risk level (low, medium, high)
        """
        new_explanation = {
            "pattern": pattern.lower(),
            "explanation": explanation,
            "risk_level": risk_level.lower()
        }
        
        # Add to explanations list
        self.explanations.append(new_explanation)
        self._save_explanations()
        
        # Update FAISS index
        embedding = self.model.encode([pattern])
        if self.index is None:
            self.index = faiss.IndexFlatL2(self.vector_dim)
        self.index.add(embedding.astype('float32'))
        faiss.write_index(self.index, str(self.index_file))
    
    def find_similar_explanations(self, text: str, top_k: int = 3) -> List[Dict]:
        """
        Find explanations similar to the input text
        
        Args:
            text: Input text to find similar explanations for
            top_k: Number of similar explanations to return
            
        Returns:
            List of similar explanations with scores
        """
        if not self.explanations or self.index is None:
            return []
        
        # Encode the input text
        query_embedding = self.model.encode([text.lower()])
        
        # Search in FAISS index
        distances, indices = self.index.search(query_embedding.astype('float32'), k=min(top_k, len(self.explanations)))
        
        # Get the most similar explanations
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.explanations):
                results.append({
                    **self.explanations[idx],
                    "similarity_score": float(1 / (1 + distances[0][i]))  # Convert distance to similarity
                })
        
        return results
    
    def generate_explanation(self, text: str, risk_factors: Dict = None) -> str:
        """
        Generate a human-readable explanation for a potential phishing attempt
        
        Args:
            text: The text to analyze
            risk_factors: Dictionary of risk factors from other analysis
            
        Returns:
            Human-readable explanation
        """
        # First try to find similar explanations in our knowledge base
        similar = self.find_similar_explanations(text, top_k=2)
        
        # If we have good matches, use them
        if similar and similar[0]["similarity_score"] > 0.7:
            explanations = [e["explanation"] for e in similar[:2]]
            return " ".join(explanations)
        
        # Otherwise, use OpenAI to generate an explanation
        if self.openai_api_key:
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert explaining why a message might be a phishing attempt. Be concise and clear."},
                        {"role": "user", "content": f"Explain why this message might be a phishing attempt in 1-2 sentences: {text}"}
                    ],
                    max_tokens=100,
                    temperature=0.3
                )
                explanation = response.choices[0].message.content.strip()
                
                # Add this explanation to our knowledge base for future use
                self.add_explanation(
                    pattern=text[:100],  # Use first 100 chars as pattern
                    explanation=explanation,
                    risk_level=risk_factors.get("risk_level", "medium") if risk_factors else "medium"
                )
                
                return explanation
                
            except Exception as e:
                self.logger.error(f"Error generating AI explanation: {str(e)}")
        
        # Fallback to a generic explanation
        return "This message contains characteristics commonly found in phishing attempts, such as suspicious links or requests for personal information."
    
    def get_recommendations(self, risk_level: str, risk_factors: Dict = None) -> List[str]:
        """
        Get recommended actions based on risk level and factors
        
        Args:
            risk_level: 'low', 'medium', or 'high'
            risk_factors: Dictionary of specific risk factors
            
        Returns:
            List of recommended actions
        """
        recommendations = {
            "high": [
                "Do not click on any links or download attachments",
                "Do not provide any personal or financial information",
                "Report this as phishing to your IT department or email provider",
                "If you're concerned about your account, contact the company directly using a verified contact method"
            ],
            "medium": [
                "Be cautious with links and attachments",
                "Verify the sender's email address is legitimate",
                "Look for signs of phishing like poor grammar or unusual requests"
            ],
            "low": [
                "Remain vigilant for suspicious requests",
                "When in doubt, verify through official channels"
            ]
        }
        
        return recommendations.get(risk_level.lower(), recommendations["medium"])

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    explainer = PhishingExplainer()
    
    # Add a custom explanation
    explainer.add_explanation(
        pattern="your account has been suspended",
        explanation="Creates fear of account loss to trick you into providing login credentials.",
        risk_level="high"
    )
    
    # Test explanation generation
    test_text = "Your bank account has been locked. Click here to unlock it now!"
    explanation = explainer.generate_explanation(test_text)
    print(f"Explanation: {explanation}")
    
    # Get recommendations
    recommendations = explainer.get_recommendations("high")
    print("\nRecommendations:")
    for rec in recommendations:
        print(f"- {rec}")
