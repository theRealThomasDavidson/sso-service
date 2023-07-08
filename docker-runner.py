import os
import shutil
from subprocess import run
from dotenv import dotenv_values
from sys import exit

def substitute_variables(template_path, output_path):
    # Read the template SQL file
    with open(template_path, 'r') as template_file:
        template = template_file.read()

    # Load environment variables from .env
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')

    # Create the substitution dictionary from dotenv variables
    substitution_dict = dict(dotenv_values(dotenv_path))

    # Perform variable substitution    
    for key, value in substitution_dict.items():
        template = template.replace('{%s}' % key, value)

    # Write the substituted SQL to the output file
    with open(output_path, 'w') as output_file:
        output_file.write(template)

def start_docker_container():
    # Run docker-compose up command
    run(['docker-compose', '-f', 'docker-compose.yml', 'up', '--build', '--force-recreate'])
def stop_docker_container():
    # Run docker-compose down command
    run(['docker-compose', '-f', 'docker-compose.yml', 'down', '--volumes', '--remove-orphans'])


if __name__ == '__main__':
    # Path to the template SQL file
    template_path = 'sql/template.sql'
    
    # Path to the output SQL file
    output_path = 'init-scripts/init.sql'
    
    # Perform variable substitution
    substitute_variables(template_path, output_path)
    # Start the Docker container
    try:
        start_docker_container()
    except:
        pass
    stop_docker_container()