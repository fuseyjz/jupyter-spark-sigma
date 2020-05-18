import socket
import os
import sys

from pyspark.sql import SparkSession
from pyspark import *
from pyspark.sql.functions import *
from pyspark.sql.types import *
from pyspark.sql import functions as F

class Spark:

    def load(self, appname, pods):
        """
            Initialise Spark Session with k8s Spark
        """
        # Get user pod IP
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name) 

        # Config Spark
        sparkConf = SparkConf()
        sparkConf.setMaster('k8s://https://xx.xx.ap-southeast-1.eks.amazonaws.com:443') 
        sparkConf.setAppName(appname) 
        sparkConf.set('spark.kubernetes.container.image', 'xx.xx.ecr.ap-southeast-1.amazonaws.com/xx:pyspark-2.4.3') 
        sparkConf.set('spark.submit.deployMode', 'client')
        sparkConf.set("spark.kubernetes.namespace", "xx-xx") 
        sparkConf.set('spark.driver.cores', '2')
        sparkConf.set('spark.driver.memory', '16g')
        sparkConf.set('spark.executor.cores', '6')
        sparkConf.set('spark.executor.memory', '16g')
        sparkConf.set('spark.executor.instances', pods)
        sparkConf.set("spark.ui.proxyBase", "")
        sparkConf.set("spark.sql.execution.arrow.enabled", "true")
        sparkConf.set("spark.sql.hive.caseSensitiveInferenceMode", "NEVER_INFER")
        sparkConf.set("spark.speculation", "false")
        sparkConf.set("spark.kubernetes.driver.annotation.iam.amazonaws.com/role", "arn:aws:iam::xx:role/s3_read_only") 
        sparkConf.set("spark.kubernetes.executor.annotation.iam.amazonaws.com/role", "arn:aws:iam::xx:role/s3_read_only") 
        sparkConf.set('spark.driver.host', host_ip)
        os.environ['PYSPARK_PYTHON'] = 'python3' 
        os.environ['PYSPARK_DRIVER_PYTHON'] = 'python3' 

        # Create Session
        spark = SparkSession.builder.config(conf=sparkConf).getOrCreate()
        spark.sparkContext.setLogLevel("ERROR")
        
        return spark

    def flatten(self, nested_df):
        """
            Simple flattening DF method for osquery log
        """
        flat_cols = [c[0] for c in nested_df.dtypes if c[1][:6] != 'struct']
        nested_cols = [c[0] for c in nested_df.dtypes if c[1][:6] == 'struct']

        flat_df = nested_df.select(flat_cols +
                                [F.col(nc+'.'+c).alias(nc+'_'+c)
                                    for nc in nested_cols
                                    for c in nested_df.select(nc+'.*').columns])
        return flat_df