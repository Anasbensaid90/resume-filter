# Import necessary libraries
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize SQLAlchemy
db = SQLAlchemy()

# User model for managing users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Function to compute similarity scores
def simil(feats, p_resumetxt, p_jdtxt):
    """
    This function returns a dataframe of similarity scores
    between resumes and job descriptions.
    :param feats: dataframe of text features
    :param p_resumetxt: preprocessed list of resume texts
    :param p_jdtxt: preprocessed list of job description texts
    :return: dataframe of similarity scores
    """
    # Calculate cosine similarity
    similarity = cosine_similarity(feats[0:len(p_resumetxt)], feats[len(p_resumetxt):])

    # Generate column names for job descriptions
    abc = [f"JD {i+1}" for i in range(len(p_jdtxt))]

    # Create DataFrame for similarity scores
    df_sim = pd.DataFrame(similarity, columns=abc)

    return df_sim

# Example usage
if __name__ == "__main__":
    # Sample feature dataframe
    feats = pd.DataFrame([
        # Add sample features here
    ])

    # Sample preprocessed texts
    p_resumetxt = [
        # Add sample resume texts here
    ]
    p_jdtxt = [
        # Add sample job description texts here
    ]

    # Calculate similarity
    df_sim = simil(feats, p_resumetxt, p_jdtxt)
    print(df_sim)
