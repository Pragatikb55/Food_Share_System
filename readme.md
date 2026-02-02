# FoodShare - Food Waste Reduction System

A web application to connect surplus food from businesses with NGOs and people in need.

## Features

### For Food Donors (Hotels, Restaurants, Events)
- Create food listings with details (type, quantity, pickup time)
- Track donation impact
- Manage multiple listings
- Get notifications when food is claimed

### For NGOs/Charities
- Browse available food donations
- Claim food with one click
- Track claimed food and distribution
- Contact donors directly
- View impact statistics

### For Administrators
- Manage all users and listings
- Send system notifications
- Generate reports
- Monitor system health

## Technology Stack

- **Backend:** Python 3, Flask
- **Frontend:** HTML, CSS, Bootstrap 5
- **Database:** PostgreSQL
- **Authentication:** Flask-Login
- **Deployment:** Heroku-ready

## Installation

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

### Step 1: Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd food_waste_system

# Run setup script
chmod +x setup.sh
./setup.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt