import pandas as pd
import matplotlib.pyplot as plt
import sqlite3 as lite
from sqlite3 import Error
from pathlib import Path
from datetime import date
import numpy as np
import seaborn as sns
import matplotlib.ticker as tick
import requests
import difflib as diff
import re
import csv
import ast
import json

# pd.set_option('mode.chained_assignment', None)

def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    conn = None
    try:
        conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
        # engine = sa.create_engine('sqlite:///' + db_file)  # connection via sqlalchemy
        # conn = engine.connect()
    except Error as e:
        print(e)
    return conn

def get_conn(DATA_PATH):
    conn = create_connection(DATA_PATH + "/CVEfixes.db")
    return conn

class ConnSearcher:
    def __init__(self, conn):
        self.conn=conn

    def query(self, select_query):

        query_result = pd.read_sql_query(
            select_query,
            self.conn
        )
        return query_result

    def get_all_languages(self):
        select_query = '''
        SELECT DISTINCT repo_language
        FROM repository;
        '''

        languages = pd.read_sql_query(
            select_query,
            self.conn
        )
        return languages

    def get_cve_by_language(self, language):
        select_query='''
            SELECT
            cve.cve_id, cve.published_date,
            fixes.hash,
            repository.repo_url
            FROM cve, fixes, commits, repository
            WHERE cve.cve_id=fixes.cve_id AND fixes.hash=commits.hash AND commits.repo_url=repository.repo_url
            AND repository.repo_language="{language}"
        '''.format(language=language)

        cves = pd.read_sql_query(
            select_query,
            self.conn
        )
        return cves

    def get_cve_desc(self, cve_id):
        select_query='''
            SELECT
            cve.description
            FROM cve
            WHERE cve.cve_id="{cve_id}"
        '''.format(cve_id=cve_id)

        cve_desc = pd.read_sql_query(
            select_query,
            self.conn
        )
        desc_str = cve_desc['description'][0]

        desc_str = desc_str.replace("[{'lang': 'en', 'value': '", '[{"lang": "en", "value": "')
        desc_str = desc_str.replace("'}]", '"}]')
        desc_str = desc_str.replace("'lang': 'en', 'value'", '"lang": "en", "value"')
        #print(desc_str)
        #cve_desc_str = json.loads(desc_str)[0]["value"]
        cve_desc_str = desc_str[
            len('[{"lang": "en", "value": "'):-3
        ]
        return cve_desc_str

    def get_cve_cwe_desc(self, cve_id):
        select_query=f'''
            SELECT
            cwe.cwe_name, cwe.description, cwe.extended_description,
            cve.description
            FROM cwe_classification cc, cwe, cve
            WHERE cve.cve_id="{cve_id}" AND cve.cve_id=cc.cve_id AND cc.cwe_id=cwe.cwe_id
        '''.format(cve_id=cve_id)

        cve_cwe_desc = pd.read_sql_query(
            select_query,
            self.conn
        )
        return cve_cwe_desc

    def get_commit_info(self, cve_id):
        select_query=f'''
        SELECT cve.cve_id, commits.hash, commits.repo_url, commits.parents
        FROM cve, fixes, commits
        WHERE cve.cve_id="{cve_id}" AND cve.cve_id=fixes.cve_id AND fixes.hash=commits.hash
        '''.format(cve_id=cve_id)
        all_kv = pd.read_sql_query(
            select_query,
            self.conn
        )
        commit_dict = all_kv.iloc[0].to_dict()
        return commit_dict

    def get_all_kv(self, table_name, pk_key, pk_val):
        select_query=f'''
        SELECT *
        FROM {table_name}
        WHERE {pk_key}="{pk_val}"
        '''.format(table_name=table_name, pk_key=pk_key, pk_val=pk_val)

        all_kv = pd.read_sql_query(
            select_query,
            self.conn
        )
        return all_kv

    def get_file_change_by_hash(self, hash):
        file_change_record=self.get_all_kv(
            table_name="file_change",
            pk_key="hash",
            pk_val=hash
        )
        return file_change_record

    def get_method_change_by_id(self, file_change_id):
        method_change_record = self.get_all_kv(
            table_name="method_change",
            pk_key="file_change_id",
            pk_val=file_change_id
        )
        return method_change_record

    def get_changes(self, cve_id):
        select_query='''
            SELECT
            cve.cve_id, fc.old_path, fc.filename, mc.name
            FROM cve, fixes, commits, file_change fc, method_change mc
            WHERE cve.cve_id="{cve_id}" 
                AND cve.cve_id=fixes.cve_id 
                AND fixes.hash=commits.hash
                AND commits.hash=fc.hash
                AND fc.file_change_id=mc.file_change_id
        '''.format(cve_id=cve_id)

        changes_df = pd.read_sql_query(
            select_query,
            self.conn
        )
        return changes_df