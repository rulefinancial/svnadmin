#!/bin/bash

BACKUP_MOUNT=/mnt/backup/rulegit2_backups

## Make sure the backup drive is mounted
if [ -e "$BACKUP_MOUNT/.ready" ]
then

  ## Login to the GitLab installation & run a backup
  su - git -c 'cd /home/git/gitlab && bundle exec rake gitlab:backup:create'

  ## Check to make sure the backup directory exists and
  ## move the backup file into that directory
  if [ ! -d "$BACKUP_MOUNT/gitlab" ]
  then
    mkdir $BACKUP_MOUNT/gitlab
  fi
  mv /home/git/gitlab/tmp/backups/*.tar $BACKUP_MOUNT/gitlab

  ## Backup the configuration directory
  echo "Backing up configuration ..."
  tar cPf /tmp/etc.tar /etc
  mv /tmp/etc.tar $BACKUP_MOUNT

  ## Backup the root home directory
  echo "Backing up root directory ..."
  tar cPf /tmp/root.tar /root
  mv /tmp/root.tar $BACKUP_MOUNT

  ## Remove old GitLab backups
  echo "Removing old GitLab backups ..."
  ls -t $BACKUP_MOUNT/gitlab/*gitlab* | awk 'NR>5 {system("rm \"" $0 "\"")}'
fi
