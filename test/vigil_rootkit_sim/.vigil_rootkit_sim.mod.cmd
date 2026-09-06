savedcmd_vigil_rootkit_sim.mod := printf '%s\n'   vigil_rootkit_sim.o | awk '!x[$$0]++ { print("./"$$0) }' > vigil_rootkit_sim.mod
