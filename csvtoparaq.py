import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

CSV_FILE = "../logs/rba-dataset.csv"
PARQUET_FILE = "bigfile.parquet"
CHUNK_SIZE = 300_000

writer = None

for chunk in pd.read_csv(CSV_FILE, chunksize=CHUNK_SIZE):
    table = pa.Table.from_pandas(chunk)

    if writer is None:
        writer = pq.ParquetWriter(PARQUET_FILE, table.schema)

    writer.write_table(table)

writer.close()
print("Conversion completed!")
