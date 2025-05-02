# CVE-Bench, in NAACL-2025

## Introduction

## Implementation

First please download and preprocess the CVEFixes database:
```shell
mkdir data
cd data
wget https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip
unzip CVEfixes_v1.0.8.zip
gzip -d  CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz
sqlite3 CVEfixes.db < CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql
```



## Citation