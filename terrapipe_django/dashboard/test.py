import requests
import pandas as pd
import math
from datetime import datetime, timedelta

def fetch_hourly_data(lat, lon, start_date, end_date):
    url = (
        f"https://power.larc.nasa.gov/api/temporal/hourly/point"
        f"?parameters=T2M,RH2M,WS2M,ALLSKY_SFC_SW_DWN,PS"
        f"&community=ag&longitude={lon}&latitude={lat}"
        f"&start={start_date}&end={end_date}&format=JSON"
    )
    response = requests.get(url)
    data = response.json()

    records = data['properties']['parameter']
    df = pd.DataFrame({
        'T2M': records['T2M'],
        'RH2M': records['RH2M'],
        'WS2M': records['WS2M'],
        'ALLSKY_SFC_SW_DWN': records['ALLSKY_SFC_SW_DWN'],
        'PS': records['PS'],
    }).T.stack().unstack(0)

    df.index = pd.to_datetime(df.index, format="%Y%m%d%H")
    return df

def calculate_hourly_eto(row, lat):
    # Skip invalid or missing data
    if (
        any(pd.isna([row['T2M'], row['RH2M'], row['WS2M'], row['ALLSKY_SFC_SW_DWN'], row['PS']])) or
        row['ALLSKY_SFC_SW_DWN'] == -999
    ):
        return float('nan')

    # Constants
    G = 0  # Soil heat flux density [MJ/m²/h]
    albedo = 0.23
    T = row['T2M']
    RH = row['RH2M']
    u2 = row['WS2M']
    Rs = row['ALLSKY_SFC_SW_DWN']
    P = row['PS'] / 10  # Convert Pa to kPa

    delta = (4098 * (0.6108 * math.exp((17.27 * T) / (T + 237.3)))) / ((T + 237.3) ** 2)
    gamma = 0.665e-3 * P
    es = 0.6108 * math.exp((17.27 * T) / (T + 237.3))
    ea = es * RH / 100
    Rns = (1 - albedo) * Rs
    eto_numerator = (0.408 * delta * (Rns - G) + gamma * (900 / (T + 273)) * u2 * (es - ea))
    eto_denominator = delta + gamma * (1 + 0.34 * u2)
    eto = eto_numerator / eto_denominator
    return round(eto, 4)


def get_hourly_eto(lat, lon, start_date=None, end_date=None):
    if end_date is None:
        end_date = datetime.utcnow().strftime("%Y%m%d")
    if start_date is None:
        start_date = (datetime.utcnow() - timedelta(days=1)).strftime("%Y%m%d")

    df = fetch_hourly_data(lat, lon, start_date, end_date)
    df['ETo'] = df.apply(lambda row: calculate_hourly_eto(row, lat), axis=1)
    return df[['ETo']]

# Example usage
lat = 28.6139  # Delhi
lon = 77.2090
eto_df = get_hourly_eto(lat, lon, start_date="20250805", end_date="20250806")

print(eto_df)
