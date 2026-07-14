#!/usr/bin/env python
import argparse

import faraday.server.config
from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.app import celery, get_app  # noqa
from faraday.server.utils.logger import setup_celery_logging

application = get_app()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--loglevel', type=str, help='Celery log level', required=False)
    parser.add_argument('--schedule', type=str, help='Path to the beat schedule state file',
                        required=False)
    args = parser.parse_args()
    print("Starting celery beat")

    loglevel = 'WARNING'
    if faraday.server.config.faraday_server.debug:
        loglevel = 'DEBUG'
    elif args.loglevel:
        loglevel = args.loglevel

    schedule = args.schedule or str(CONST_FARADAY_HOME_PATH / 'celerybeat-schedule')

    setup_celery_logging()

    # Run exactly one beat process per deployment.
    celery.start(
        argv=[
            'beat',
            '--loglevel',
            loglevel,
            '--schedule',
            schedule,
        ]
    )


if __name__ == '__main__':
    main()
