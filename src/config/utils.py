import pandas as pd
from pandas import DataFrame
from analysis_graph.config.ios_version_config import VERSION_MAP
from analysis_graph.config.ios_version_config import VERSION_ORDER
from analysis_graph.config.ios_version_config import IOS_VERSION

def load_ios_versions_in_data_frame(df: DataFrame):
    df[IOS_VERSION] = df[IOS_VERSION].map(VERSION_MAP).fillna(df[IOS_VERSION])
    df[IOS_VERSION] = pd.Categorical(df[IOS_VERSION], categories=VERSION_ORDER, ordered=True)
    return df