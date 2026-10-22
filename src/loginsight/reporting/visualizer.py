import matplotlib.pyplot as plt

def plot_status_codes(df):
    status_counts = df['status'].value_counts()
    status_counts.plot(kind='bar', color='skyblue')
    plt.title("Status Code Distribution")
    plt.xlabel("Status Code")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig("status_codes.png")
    plt.close()

def plot_requests_by_hour(df):
    df['hour'] = df['time'].dt.hour
    df['hour'].value_counts().sort_index().plot(kind='line', marker='o')
    plt.title("Requests per Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Number of Requests")
    plt.tight_layout()
    plt.savefig("requests_by_hour.png")
    plt.close()