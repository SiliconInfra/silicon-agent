from django.core.management import BaseCommand
from collector.dmidecode import DMI


class Command(BaseCommand):
	def handle(self, *args, **options):
		dmi = DMI()
		output = dmi.command(run_with_sudo=True)
		parsed_data = dmi.parse(output)
		print(dmi.get_by_type(parsed_data, "BIOS"))
