FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy
RUN useradd -m -s /bin/bash pwuser
WORKDIR /app
COPY src/ .
RUN pip install beautifulsoup4 python-whois pandas lightgbm joblib
RUN chown -R pwuser:pwuser /app
USER pwuser
ENTRYPOINT ["python", "gatekeeper.py"]