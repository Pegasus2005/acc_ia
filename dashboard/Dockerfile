FROM python:3.11-slim

RUN groupadd -r dashboard && useradd -r -g dashboard dashboard

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER dashboard

EXPOSE 8501

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["streamlit", "run", "Home.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false", \
     "--theme.base=dark", \
     "--theme.backgroundColor=#020817", \
     "--theme.primaryColor=#06b6d4", \
     "--theme.secondaryBackgroundColor=#0f172a", \
     "--theme.textColor=#e2e8f0"]
