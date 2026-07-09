from sqlalchemy import create_engine

from config.settings import DATABASE

engine = create_engine(f"sqlite:///{DATABASE}", echo=False)

def init_database():
    with engine.connect():
        print("✓ SQLite database initialized")