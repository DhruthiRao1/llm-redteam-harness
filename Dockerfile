FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY redteam ./redteam
RUN pip install --no-cache-dir .
ENTRYPOINT ["redteam"]
CMD ["--target", "mock-guarded"]
