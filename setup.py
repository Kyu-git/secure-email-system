from setuptools import setup, find_packages

setup(
    name="secure-email-system",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'Flask==2.0.1',
        'SQLAlchemy==1.4.23',
        'cryptography==3.4.7',
        'PyJWT==2.1.0',
        'python-dotenv==0.19.0',
        'flask-cors==3.0.10',
        'flask-mail==0.9.1',
        'flask-sqlalchemy==2.5.1',
        'pycryptodome==3.10.1',
        'email-validator==1.1.3',
        'python-magic==0.4.24',
        'gunicorn==20.1.0',
        'psycopg2-binary==2.9.3'
    ],
    python_requires='>=3.7',
) 