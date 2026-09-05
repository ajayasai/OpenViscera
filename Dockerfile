FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OV_DATA=/data OV_ORIGIN=https://localhost
WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . && \
    useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
ENTRYPOINT ["openviscera"]
CMD ["serve", "--data", "/data", "--host", "0.0.0.0", "--port", "8000"]
