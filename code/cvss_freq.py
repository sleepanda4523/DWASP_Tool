import numpy as np
import pandas as pd
from cwe import Database


class final:
    savedir = "../data/"
    df = pd.DataFrame()
    db = Database()
    resultdir = '../result/'

    def make_final(self):
        cvss_df = self.df.sort_values(by='CVSS', axis=0, ascending=False).reset_index().drop(['index', 'CVE-ID'], axis=1)
        cvss_df = cvss_df[cvss_df['CWE-NAME'] != "Nop"]
        cvss_df = cvss_df.drop_duplicates(['CWE-ID'])
        freq_df = pd.read_excel(self.resultdir + 'freq.xlsx')
        result_df = pd.merge(cvss_df, freq_df, on='CWE-NAME')
        result_df.sort_values(by=['CVSS', 'count'], ascending=[False, False]).to_excel(self.resultdir + 'final1.xlsx', engine='xlsxwriter')
        result_df.sort_values(by=['count', 'CVSS'], ascending=[False, False]).to_excel(self.resultdir + 'final2.xlsx', engine='xlsxwriter')