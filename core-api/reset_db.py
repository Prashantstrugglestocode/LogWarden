from database import engine, Base
from models import Log
import sys

def reset_db():
    print("Dropping logs table...")
    try:
        Log.__table__.drop(engine)
        print("Table dropped.")
    except Exception as e:
        print(f"Error dropping table (might not exist): {e}")

    print("Recreating tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")

if __name__ == "__main__":
    reset_db()
