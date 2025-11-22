import pandas as pd


def main():
    # Read the techniques CSV
    df = pd.read_csv(".data/techniques.csv")

    # Select and prepare columns
    df = df[
        [
            "ID",
            "name",
            "description",
            "url",
            "domain",
            "tactics",
            "is sub-technique",
            "sub-technique of",
        ]
    ]
    df["tactics"] = df["tactics"].apply(lambda x: x.split(",") if "," in x else [x])

    # Split into parent and child dataframes
    df_parent = df[df["is sub-technique"] == False][
        ["ID", "name", "description", "url", "domain", "tactics"]
    ].rename(columns={"ID": "technique_id"})
    df_child = df[df["is sub-technique"] == True][
        ["ID", "name", "description", "url", "domain", "tactics", "sub-technique of"]
    ].rename(columns={"ID": "technique_id", "sub-technique of": "parent_id"})

    # Create tactics mapping table
    rows = []
    for index, row in df_parent.iterrows():
        for tactic in row["tactics"]:
            rows.append(
                {
                    "technique_id": row["technique_id"],
                    "tactic": tactic,
                }
            )
    df_tactics = pd.DataFrame(rows)

    # Clean up parent dataframe to remove tactics column
    df_parent = df_parent[["technique_id", "name", "description", "url", "domain"]]

    # Save to CSV files
    df_parent.to_csv(".data/parent.csv", index=False)
    df_tactics.to_csv(".data/tactics.csv", index=False)

    print(f"Successfully processed {len(df_parent)} parent techniques")
    print(f"Created {len(df_tactics)} tactic mappings")
    print("Output files: parent.csv, tactics.csv")


if __name__ == "__main__":
    main()
