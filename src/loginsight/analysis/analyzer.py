import pandas as pd


def analyze_entries(entries):
    df = pd.DataFrame(entries)

    stats = {
        'total_requests': len(df),
        'unique_ips': df['ip'].nunique(),
        'most_common_ips': df['ip'].value_counts().head(5).to_dict(),
        'most_requested_paths': df['path'].value_counts().head(5).to_dict(),
        'status_code_counts': df['status'].value_counts().to_dict(),
        'total_data_transferred_MB': round(df['size'].sum() / 1024 / 1024, 2)
    }

    return df, stats