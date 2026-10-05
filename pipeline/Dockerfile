FROM apache/airflow:3.3.2-python3.11

USER airflow
RUN pip install --no-cache-dir \
	clickhouse-connect \
	polars \
	pyarrow \
	python-dotenv
