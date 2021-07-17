from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy_utils import EmailType
from .database import Base


class User(Base):
    __tablename__ = "users"

    identification = Column(Integer, primary_key=True)
    created_date = Column(DateTime)
    username = Column(EmailType)
    password = Column(String)
    is_superuser = Column(Boolean, default=True)
