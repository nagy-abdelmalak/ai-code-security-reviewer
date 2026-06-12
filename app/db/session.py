from sqlmodel import SQLModel, create_engine, Session, Field

settings = get_settings()

engine = create_engine(settings.DATABASE_URL, echo=(settings.ENVIRONMENT == "development"))

def get_session():
    with Session(engine) as session:
        yield session