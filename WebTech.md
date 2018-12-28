# Web Tech

**Client Server Model**

**App and Web Servers**

**NGNIXii**

**PostgreSQL**

How does the Calculator work? You put in a URL, such as

https://www.at-bay.com/bp/api/gui/v1/financial_exposure/calculate?record_owner=customer_and_employee&num_records=100000000&record_type=PHI-PCI&breach_type=hack&recent_breach=true&percent_addr_stored=100

where you can modify record_owner, num_records, record_type, breach_type, recent_breach, percent_addr_stored

and it gives you back a json object, such as 

{"result": {"breach_coach": 25000, "call_center": 1300, "class_action_fines_and_defense": 0, "credit_monitoring": 60, "crisis_management": 40000, "forensics": 120000, "notification": 2900, "pci_fines": 76000, "regulatory_fines_and_defense": 1200000}, "total": 1465260, "cost_per_record": 32561.333333333332}

where the result has breach_coach, call_center, class_action_fines_and_defense, credit_monitoring, crisis_management, forensics, notification, pci_fines, regulatory_fines_and_defense, total, cost_per_record


