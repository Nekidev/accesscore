docker exec -it accesscore-scylla-dev-main nodetool drain
docker exec -it accesscore-scylla-dev-1 nodetool drain
docker exec -it accesscore-scylla-dev-2 nodetool drain

docker exec -it accesscore-scylla-dev-main supervisorctl stop scylla
docker exec -it accesscore-scylla-dev-1 supervisorctl stop scylla
docker exec -it accesscore-scylla-dev-2 supervisorctl stop scylla

docker compose --profile dev down
