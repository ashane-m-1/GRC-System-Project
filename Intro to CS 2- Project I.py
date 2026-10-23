"""
Cybersecurity GRC System
------------------------

Functions:
1. Calculate Risk Score
2. Check Security Control
3. Create Risk Summary

Data Source:
NIST SP 800-53 Security and Privacy Controls
https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads

Required CSV:
Download the NIST SP 800-53 Controls CSV and place it in the
same folder as this Python file.

Recommended filename:
sp800-53-controls.csv
"""

import csv
import os
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = r"C:\Ash Folder\ITSC 1213- Project I\risk_register.csv"
RISK_FILE = "risk_register.csv"


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def clear_screen():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    """Pause before returning to the menu."""
    input("\nPress Enter to continue...")


def print_header(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(title.center(70))
    print("=" * 70)


# ============================================================
# FUNCTION 1: CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score():
    """
    Calculate risk score using:

        Risk Score = Likelihood × Impact

    Likelihood:
        1 = Rare
        2 = Unlikely
        3 = Possible
        4 = Likely
        5 = Almost Certain

    Impact:
        1 = Negligible
        2 = Minor
        3 = Moderate
        4 = Major
        5 = Severe
    """

    print_header("FUNCTION 1 - CALCULATE RISK SCORE")

    print("Enter values from 1 to 5.")
    print()
    print("Likelihood:")
    print("1 - Rare")
    print("2 - Unlikely")
    print("3 - Possible")
    print("4 - Likely")
    print("5 - Almost Certain")

    print()

    # Get likelihood
    while True:
        try:
            likelihood = int(input("Enter likelihood (1-5): "))

            if 1 <= likelihood <= 5:
                break

            print("Please enter a number between 1 and 5.")

        except ValueError:
            print("Invalid input. Please enter a number.")

    print()

    print("Impact:")
    print("1 - Negligible")
    print("2 - Minor")
    print("3 - Moderate")
    print("4 - Major")
    print("5 - Severe")

    print()

    # Get impact
    while True:
        try:
            impact = int(input("Enter impact (1-5): "))

            if 1 <= impact <= 5:
                break

            print("Please enter a number between 1 and 5.")

        except ValueError:
            print("Invalid input. Please enter a number.")

    # Calculate score
    risk_score = likelihood * impact

    # Determine risk level
    if risk_score <= 4:
        risk_level = "LOW"
    elif risk_score <= 9:
        risk_level = "MEDIUM"
    elif risk_score <= 16:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    print("\n" + "-" * 50)
    print("RISK ASSESSMENT RESULT")
    print("-" * 50)

    print(f"Likelihood : {likelihood}")
    print(f"Impact     : {impact}")
    print(f"Risk Score : {risk_score}/25")
    print(f"Risk Level : {risk_level}")

    print("-" * 50)

    return risk_score, risk_level


# ============================================================
# NIST CSV LOADING
# ============================================================

def load_nist_controls():
    """
    Load NIST SP 800-53 controls from CSV.

    The function attempts to identify common column names
    automatically because NIST CSV versions can have slightly
    different headers.
    """

    if not os.path.exists(CSV_FILE):
        print("\nERROR: NIST CSV file was not found.")
        print()
        print(f"Expected file: {CSV_FILE}")
        print()
        print("Download the NIST SP 800-53 CSV and place it in")
        print("the same folder as this Python program.")
        print()
        print("NIST download page:")
        print("https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads")

        return []

    controls = []

    try:
        # Try UTF-8 first
        try:
            file = open(
                CSV_FILE,
                "r",
                encoding="utf-8-sig",
                newline=""
            )
        except UnicodeDecodeError:
            file = open(
                CSV_FILE,
                "r",
                encoding="latin-1",
                newline=""
            )

        with file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                print("ERROR: CSV does not contain column headers.")
                return []

            fieldnames = reader.fieldnames

            # Normalize field names
            normalized_fields = {
                field.strip().lower(): field
                for field in fieldnames
            }

            # Find control ID column
            control_id_column = None

            possible_id_columns = [
                "control identifier",
                "control id",
                "control",
                "id",
                "identifier",
                "controlidentifier"
            ]

            for possible in possible_id_columns:
                if possible in normalized_fields:
                    control_id_column = normalized_fields[possible]
                    break

            # Find title/name column
            title_column = None

            possible_title_columns = [
                "control name",
                "name",
                "title",
                "control title",
                "controlname"
            ]

            for possible in possible_title_columns:
                if possible in normalized_fields:
                    title_column = normalized_fields[possible]
                    break

            # Find description column
            description_column = None

            possible_description_columns = [
                "control statement",
                "description",
                "control description",
                "discussion",
                "controlstatement",
                "control description/statement"
            ]

            for possible in possible_description_columns:
                if possible in normalized_fields:
                    description_column = normalized_fields[possible]
                    break

            # Read rows
            for row in reader:

                control_id = ""

                if control_id_column:
                    control_id = row.get(control_id_column, "").strip()

                title = ""

                if title_column:
                    title = row.get(title_column, "").strip()

                description = ""

                if description_column:
                    description = row.get(description_column, "").strip()

                # If the CSV has a useful control ID, save it
                if control_id:
                    controls.append({
                        "id": control_id,
                        "title": title,
                        "description": description,
                        "raw": row
                    })

            print(f"\nLoaded {len(controls)} NIST controls.")

            return controls

    except Exception as error:
        print("\nERROR while reading NIST CSV:")
        print(error)

        return []


# ============================================================
# FUNCTION 2: CHECK SECURITY CONTROL
# ============================================================

def check_security_control():
    """
    Search the NIST SP 800-53 control catalog.

    User can search by:
        - Control ID
        - Control name
        - Keyword
    """

    print_header("FUNCTION 2 - CHECK SECURITY CONTROL")

    controls = load_nist_controls()

    if not controls:
        pause()
        return

    print("\nExamples:")
    print("  AC-2")
    print("  AC-3")
    print("  access control")
    print("  audit")
    print("  encryption")
    print()

    search_term = input("Enter control ID or keyword: ").strip()

    if not search_term:
        print("Search cannot be empty.")
        pause()
        return

    search_term_lower = search_term.lower()

    matches = []

    for control in controls:

        control_id = control["id"].lower()
        title = control["title"].lower()
        description = control["description"].lower()

        if (
            search_term_lower in control_id
            or search_term_lower in title
            or search_term_lower in description
        ):
            matches.append(control)

    if not matches:
        print("\nNo matching security controls were found.")
        pause()
        return

    print(f"\nFound {len(matches)} matching control(s).")

    # Limit results displayed
    display_matches = matches[:20]

    for index, control in enumerate(display_matches, start=1):

        print("\n" + "-" * 70)
        print(f"[{index}] {control['id']}")

        if control["title"]:
            print(f"Title: {control['title']}")

        if control["description"]:
            description = control["description"]

            # Make long descriptions easier to read
            if len(description) > 1000:
                description = description[:1000] + "..."

            print(f"Description: {description}")

    if len(matches) > 20:
        print("\nOnly the first 20 results are displayed.")

    pause()


# ============================================================
# RISK REGISTER
# ============================================================

def create_risk_file_if_needed():
    """Create risk register CSV if it does not already exist."""

    if not os.path.exists(RISK_FILE):

        headers = [
            "Date",
            "Risk ID",
            "Risk Name",
            "Description",
            "Likelihood",
            "Impact",
            "Risk Score",
            "Risk Level",
            "Security Control",
            "Status"
        ]

        with open(
            RISK_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)
            writer.writerow(headers)


def get_next_risk_id():
    """Generate the next risk ID."""

    create_risk_file_if_needed()

    risk_numbers = []

    try:

        with open(
            RISK_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                risk_id = row.get("Risk ID", "")

                if risk_id.upper().startswith("RISK-"):

                    try:
                        number = int(
                            risk_id.split("-")[1]
                        )

                        risk_numbers.append(number)

                    except (ValueError, IndexError):
                        pass

    except FileNotFoundError:
        pass

    if not risk_numbers:
        next_number = 1
    else:
        next_number = max(risk_numbers) + 1

    return f"RISK-{next_number:03d}"


def save_risk(
    risk_name,
    description,
    likelihood,
    impact,
    risk_score,
    risk_level,
    security_control,
    status
):
    """Save a risk to the risk register."""

    create_risk_file_if_needed()

    risk_id = get_next_risk_id()

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(
        RISK_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            date,
            risk_id,
            risk_name,
            description,
            likelihood,
            impact,
            risk_score,
            risk_level,
            security_control,
            status
        ])

    return risk_id


# ============================================================
# FUNCTION 3: CREATE RISK SUMMARY
# ============================================================

def create_risk_summary():
    """
    Create a risk entry and display a summary.
    """

    print_header("FUNCTION 3 - CREATE RISK SUMMARY")

    risk_name = input("Enter risk name: ").strip()

    if not risk_name:
        risk_name = "Unnamed Risk"

    print()

    description = input(
        "Enter risk description: "
    ).strip()

    print()

    # Likelihood
    while True:

        try:

            likelihood = int(
                input("Enter likelihood (1-5): ")
            )

            if 1 <= likelihood <= 5:
                break

            print("Please enter a number from 1 to 5.")

        except ValueError:
            print("Please enter a valid number.")

    # Impact
    while True:

        try:

            impact = int(
                input("Enter impact (1-5): ")
            )

            if 1 <= impact <= 5:
                break

            print("Please enter a number from 1 to 5.")

        except ValueError:
            print("Please enter a valid number.")

    # Calculate score
    risk_score = likelihood * impact

    if risk_score <= 4:
        risk_level = "LOW"

    elif risk_score <= 9:
        risk_level = "MEDIUM"

    elif risk_score <= 16:
        risk_level = "HIGH"

    else:
        risk_level = "CRITICAL"

    print()
    security_control = input(
        "Enter related NIST control (example: AC-2): "
    ).strip()

    if not security_control:
        security_control = "Not specified"

    print()
    print("Risk status options:")
    print("1 - Open")
    print("2 - Mitigated")
    print("3 - Accepted")
    print("4 - Transferred")

    while True:

        status_choice = input(
            "Select status (1-4): "
        ).strip()

        status_map = {
            "1": "Open",
            "2": "Mitigated",
            "3": "Accepted",
            "4": "Transferred"
        }

        if status_choice in status_map:
            status = status_map[status_choice]
            break

        print("Please choose 1, 2, 3, or 4.")

    # Save risk
    risk_id = save_risk(
        risk_name,
        description,
        likelihood,
        impact,
        risk_score,
        risk_level,
        security_control,
        status
    )

    # Display summary
    print("\n" + "=" * 70)
    print("RISK SUMMARY".center(70))
    print("=" * 70)

    print(f"Risk ID          : {risk_id}")
    print(f"Risk Name        : {risk_name}")
    print(f"Description      : {description}")
    print(f"Likelihood       : {likelihood}")
    print(f"Impact           : {impact}")
    print(f"Risk Score       : {risk_score}/25")
    print(f"Risk Level       : {risk_level}")
    print(f"Security Control : {security_control}")
    print(f"Status           : {status}")

    print("=" * 70)

    print(f"\nRisk saved to: {RISK_FILE}")

    pause()


# ============================================================
# VIEW RISK REGISTER
# ============================================================

def view_risk_register():
    """Display all saved risks."""

    print_header("RISK REGISTER")

    create_risk_file_if_needed()

    try:

        with open(
            RISK_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            risks = list(reader)

    except Exception as error:

        print(f"Error reading risk register: {error}")

        pause()
        return

    if not risks:

        print("No risks have been registered yet.")

        pause()
        return

    for risk in risks:

        print("\n" + "-" * 70)

        print(
            f"{risk.get('Risk ID', '')} | "
            f"{risk.get('Risk Name', '')}"
        )

        print(
            f"Score: {risk.get('Risk Score', '')}/25 | "
            f"Level: {risk.get('Risk Level', '')}"
        )

        print(
            f"Likelihood: {risk.get('Likelihood', '')} | "
            f"Impact: {risk.get('Impact', '')}"
        )

        print(
            f"Control: {risk.get('Security Control', '')}"
        )

        print(
            f"Status: {risk.get('Status', '')}"
        )

        print(
            f"Description: {risk.get('Description', '')}"
        )

    print("\n" + "-" * 70)

    pause()


# ============================================================
# RISK STATISTICS
# ============================================================

def risk_statistics():
    """Display basic risk statistics."""

    print_header("RISK STATISTICS")

    create_risk_file_if_needed()

    try:

        with open(
            RISK_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            risks = list(reader)

    except Exception as error:

        print(f"Error: {error}")

        pause()
        return

    if not risks:

        print("No risks found.")

        pause()
        return

    total = len(risks)

    low = 0
    medium = 0
    high = 0
    critical = 0

    open_risks = 0
    mitigated = 0
    accepted = 0
    transferred = 0

    total_score = 0

    for risk in risks:

        level = risk.get("Risk Level", "").upper()

        if level == "LOW":
            low += 1

        elif level == "MEDIUM":
            medium += 1

        elif level == "HIGH":
            high += 1

        elif level == "CRITICAL":
            critical += 1

        status = risk.get("Status", "").lower()

        if status == "open":
            open_risks += 1

        elif status == "mitigated":
            mitigated += 1

        elif status == "accepted":
            accepted += 1

        elif status == "transferred":
            transferred += 1

        try:
            total_score += int(
                risk.get("Risk Score", 0)
            )
        except ValueError:
            pass

    average_score = total_score / total

    print(f"Total Risks       : {total}")
    print()
    print("Risk Levels")
    print(f"Low               : {low}")
    print(f"Medium            : {medium}")
    print(f"High              : {high}")
    print(f"Critical          : {critical}")
    print()
    print("Risk Status")
    print(f"Open              : {open_risks}")
    print(f"Mitigated         : {mitigated}")
    print(f"Accepted          : {accepted}")
    print(f"Transferred       : {transferred}")
    print()
    print(f"Average Risk Score: {average_score:.2f}/25")

    pause()

# ===============================================
# DELETE RISK
# ===============================================
def delete_risk():
    """Delete a risk from the risk register."""

    print_header("DELETE RISK")

    create_risk_file_if_needed()

    risk_id = input("Enter the Risk ID to delete (example: RISK-001): ").strip()

    if not risk_id:
        print("Risk ID cannot be empty.")
        pause()
        return

    try:
        with open(
            RISK_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)
            risks = list(reader)
            fieldnames = reader.fieldnames

    except Exception as error:
        print(f"Error reading risk register: {error}")
        pause()
        return

    # Find the risk
    matching_risk = None

    for risk in risks:
        if risk.get("Risk ID", "").upper() == risk_id.upper():
            matching_risk = risk
            break

    if matching_risk is None:
        print(f"\nRisk '{risk_id}' was not found.")
        pause()
        return

    # Show risk before deleting
    print("\nRisk found:")
    print("-" * 50)
    print(f"Risk ID    : {matching_risk.get('Risk ID', '')}")
    print(f"Risk Name  : {matching_risk.get('Risk Name', '')}")
    print(f"Risk Score : {matching_risk.get('Risk Score', '')}")
    print(f"Risk Level : {matching_risk.get('Risk Level', '')}")
    print("-" * 50)

    confirmation = input(
        "\nAre you sure you want to delete this risk? (y/n): "
    ).strip().lower()

    if confirmation != "y":
        print("\nDeletion cancelled.")
        pause()
        return

    # Remove the selected risk
    risks = [
        risk for risk in risks
        if risk.get("Risk ID", "").upper() != risk_id.upper()
    ]

    # Rewrite the CSV file
    with open(
        RISK_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(risks)

    print(f"\nRisk {risk_id} has been deleted successfully.")

    pause()






# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        print_header("CYBERSECURITY GRC SYSTEM")

        print("1. Calculate Risk Score")
        print("2. Check Security Control")
        print("3. Create Risk Summary")
        print("4. View Risk Register")
        print("5. View Risk Statistics")
        print("6. Delete Risk")
        print("7. Exit")


        print()

        choice = input(
            "Select an option (1-7): "
        ).strip()

        if choice == "1":

            calculate_risk_score()
            pause()

        elif choice == "2":

            check_security_control()

        elif choice == "3":

            create_risk_summary()

        elif choice == "4":

            view_risk_register()

        elif choice == "5":

            risk_statistics()

        elif choice == "6":

            delete_risk()

        elif choice == "7":

            print("\nThank you for using the Cybersecurity GRC System.")
            print("Goodbye!")

            break


        else:

            print("\nInvalid option.")
            print("Please choose a number from 1 to 6.")

            pause()


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()
