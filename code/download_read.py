from requests import get
import gzip
from tqdm import *
import numpy as np
import pandas as pd
import datetime
import os.path
import pymysql


class MakeDataset:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    savedir = "../data/"
    savezip = ""
    savepath = "../data/cve_data.json"

    def __init__(self):
        d = datetime.datetime.now()
        file_list = os.listdir(self.savedir)
        gzip_file = ""
        for i in file_list:
            text = i.split('.')[-1]
            if text in "gz":
                gzip_file = i
                break

        newFilename = self.savedir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
        if len(gzip_file) == 0:
            print("Not File Have")
            self.savezip = newFilename
        else:
            gzip_file = self.savedir + gzip_file
            if newFilename != gzip_file:
                print("Need Update File")
                os.remove(gzip_file)
                print("Delete past File")
                self.savezip = newFilename
            else:
                print("Have File")
                self.savezip = gzip_file
        if not os.path.isfile(self.savezip):
            self.download()
        if not os.path.isfile(self.savepath):
            self.open_gz()

    def download(self):
        with get(self.datadump, stream=True) as r:
            r.raise_for_status()
            print('Datadump Downloading....')
            with open(self.savezip, "wb") as file:
                pbar = tqdm(total=int(r.headers['Content-Length']))
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        pbar.update(len(chunk))
        print('Datadump Downloaded')

    def open_gz(self):
        with open(self.savepath, 'wb') as f:
            print('gzip Opening...')
            with gzip.open(self.savezip, 'rb') as ff:
                file_content = ff.read()
                f.write(file_content)
        print('gzip Opened')

    def clean_dataset(self, sy, ey):
        json_df = pd.read_json(self.savepath, lines=True)
        print("Makeing Dataset...")
        year = [i for i in range(sy, ey + 1)]
        year_str = ""
        for i in year:
            year_str += ('CVE-' + str(i) + '|')
        year_str = year_str[:-1]
        contain = json_df['id'].str.contains(year_str)
        subset_df = json_df[contain].sort_values(by='id')

        # Modify Dataset
        subset_df = subset_df.drop(subset_df.loc[subset_df['cvss'].isnull()].index)
        subset_df = subset_df.drop(subset_df.loc[subset_df['cwe'] == 'Unknown'].index)
        subset_df = subset_df.drop_duplicates(subset=['id']).sort_values(by='id')

        subset_df.to_excel(self.savedir + 'dataset.xlsx',engine='xlsxwriter')
        print('Made Dataset')

    def make_db_dataset(self, host, port, user, pw, db, query):
        conn = pymysql.connect(host=host, port=port, user=user, password=pw, db=db)
        print("Finding DB...")
        result_df = pd.read_sql(query, conn)
        """
        select code
        """
        result_df.to_excel(self.savedir + 'dataset.xlsx',engine='xlsxwriter')
        conn.close()


# testing code
# if __name__ == "__main__" :
#     test = MakeDataset()
#     test.clean_dataset(2019,2020)
