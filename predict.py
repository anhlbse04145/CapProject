import pandas as pd
# import numpy as np
# import sys
# import sklearn
# import sklearn.preprocessing
# from sklearn.cluster import KMeans
# from sklearn.feature_selection import SelectPercentile, f_classif
import joblib


def predict(featureTotalArray):

    resultFinal = []
    col_names1 = ["w1", "w2", "w3", "w4", "w5", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                  "11", "12"]
    predictfile = pd.DataFrame(data=featureTotalArray, columns=col_names1)
    predictfile = predictfile.drop(["w1", "w2", "w3", "w4", "w5"], axis=1)
    col_names2 = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                  "11", "12"]
    for col_names2 in predictfile.columns:
        predictfile[col_names2] = predictfile[col_names2].astype(float)

    filename = 'finalized_model.sav'
    filename2 = 'finalized_scaler.sav'
    loaded_scaler = joblib.load(filename2)
    predictfile = loaded_scaler.transform(predictfile)
    loaded_model = joblib.load(filename)

    result = loaded_model.predict(predictfile)

    for index, data in enumerate(featureTotalArray):
        array = data
        label = "Normal"
        if result[index] == 1.0:
            label = "Abnormal"
        array.append(label)
        resultFinal.append(array)

    print(resultFinal)
