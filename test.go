package main

import (
	"fmt"
	"os/exec"
)

func TestCode() {
	cmd := exec.Command("sleep", "2")
	err := cmd.Run()
	
	p, err := exec.LookPath("docker")

	if err != nil {
		panic(err)
	}

	fmt.Println(p)
	if err != nil {
		panic(err)
	}
}
