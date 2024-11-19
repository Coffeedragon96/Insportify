import os
import django
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Insportify.settings')
django.setup()

# Step 2: Import models or other project dependencies
from EventsApp.models import master_table

# Step 3: Add the logic you want to execute
def update_hours_for_event():
    events = master_table.objects.all()
    for event in events:
        datetimes = event.datetimes
        if datetimes:
            start_time = datetimes.split(' - ')[0].strip()
            end_time = datetimes.split(' - ')[1].strip()
            total_time = 0
            if start_time and end_time:
                start_time = start_time.split(' ')[1].strip()
                end_time = end_time.split(' ')[1].strip()
                start_time_list = start_time.split(':')
                end_time_list = end_time.split(':')
                total_time = (int(end_time_list[0]) - int(start_time_list[0])) + ((int(end_time_list[1]) - int(start_time_list[1])) / 60)
                event.total_time = total_time
                event.save()

if __name__ == "__main__":
    update_hours_for_event()
