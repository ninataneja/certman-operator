men=( namespace.yaml role.yaml service_account.yaml role_binding.yaml operator.yaml prometheus-k8s-role.yaml prometheus-k8s-rolebinding.yaml )

for man in "${men[@]}"; do 
  oc apply -f $man 
done 
