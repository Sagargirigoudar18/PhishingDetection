import numpy as np
import faiss
import pickle
import os
from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer
import logging

logger = logging.getLogger(__name__)

class VectorStore:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", dimension: int = 384):
        """
        Initialize the vector store for similarity search
        
        Args:
            model_name: Name of the sentence transformer model
            dimension: Dimension of the embeddings
        """
        self.model = SentenceTransformer(model_name)
        self.dimension = dimension
        self.index = None
        self.texts = []
        self.metadata = []
        self.index_file = "data/vector_store.faiss"
        self.texts_file = "data/vector_store_texts.pkl"
        self.metadata_file = "data/vector_store_metadata.pkl"
        
        # Create data directory if it doesn't exist
        os.makedirs("data", exist_ok=True)
        
        # Initialize or load the index
        self._initialize_index()
    
    def _initialize_index(self):
        """Initialize or load the FAISS index"""
        if os.path.exists(self.index_file) and os.path.exists(self.texts_file):
            try:
                self.index = faiss.read_index(self.index_file)
                with open(self.texts_file, 'rb') as f:
                    self.texts = pickle.load(f)
                with open(self.metadata_file, 'rb') as f:
                    self.metadata = pickle.load(f)
                logger.info(f"Loaded {len(self.texts)} items from vector store")
            except Exception as e:
                logger.error(f"Error loading vector store: {str(e)}")
                self.index = faiss.IndexFlatL2(self.dimension)
        else:
            self.index = faiss.IndexFlatL2(self.dimension)
            logger.info("Created new vector store index")
    
    def add_texts(self, texts: List[str], metadata: List[Dict[str, Any]] = None):
        """
        Add texts to the vector store
        
        Args:
            texts: List of texts to add
            metadata: Optional metadata for each text
        """
        if not texts:
            return
        
        # Generate embeddings
        embeddings = self.model.encode(texts, show_progress_bar=False)
        
        # Add to index
        self.index.add(embeddings.astype('float32'))
        
        # Store texts and metadata
        self.texts.extend(texts)
        if metadata:
            self.metadata.extend(metadata)
        else:
            self.metadata.extend([{} for _ in texts])
        
        # Save to disk
        self._save()
        logger.info(f"Added {len(texts)} texts to vector store")
    
    def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar texts
        
        Args:
            query: Query text
            k: Number of results to return
            
        Returns:
            List of dictionaries containing text, metadata, and similarity score
        """
        if not self.texts:
            return []
        
        # Generate query embedding
        query_embedding = self.model.encode([query])
        
        # Search in index
        distances, indices = self.index.search(query_embedding.astype('float32'), k=min(k, len(self.texts)))
        
        # Format results
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.texts):
                results.append({
                    'text': self.texts[idx],
                    'metadata': self.metadata[idx] if idx < len(self.metadata) else {},
                    'similarity': float(1 / (1 + distances[0][i]))  # Convert distance to similarity
                })
        
        return results
    
    def _save(self):
        """Save the vector store to disk"""
        try:
            faiss.write_index(self.index, self.index_file)
            with open(self.texts_file, 'wb') as f:
                pickle.dump(self.texts, f)
            with open(self.metadata_file, 'wb') as f:
                pickle.dump(self.metadata, f)
        except Exception as e:
            logger.error(f"Error saving vector store: {str(e)}")
    
    def clear(self):
        """Clear the vector store"""
        self.index = faiss.IndexFlatL2(self.dimension)
        self.texts = []
        self.metadata = []
        self._save()
        logger.info("Cleared vector store")
