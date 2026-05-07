# POSIX shell helpers for dotseal.
#
# Usage:
#   . /path/to/dotseal.sh
#   dotseal_load . prod
#   dotseal_exec . prod npm run deploy

dotseal_load() {
  _dotseal_path=${1:-.}
  _dotseal_scope=${2:-default}
  if [ "$_dotseal_scope" = default ]; then
    eval "$(dotseal print-env "$_dotseal_path")"
  else
    eval "$(dotseal -s "$_dotseal_scope" print-env "$_dotseal_path")"
  fi
}

dotseal_exec() {
  _dotseal_path=${1:-.}
  _dotseal_scope=${2:-default}
  shift 2
  if [ "$_dotseal_scope" = default ]; then
    dotseal exec "$_dotseal_path" "$@"
  else
    dotseal -s "$_dotseal_scope" exec "$_dotseal_path" "$@"
  fi
}
