package br.com.barry.todolist.task;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.barry.todolist.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/tasks")
public class TaskController {

  @Autowired
  private ITaskRepository taskRepository;

  @PostMapping("/")
  public ResponseEntity<?> create(@RequestBody TaskModel taskModel, HttpServletRequest request) {
    var idUser = request.getAttribute("idUser");
    taskModel.setIdUser((UUID) idUser);

    var taskStartDate = taskModel.getStartAt();
    var taskEndDate = taskModel.getEndAt();
    LocalDateTime currentDate = LocalDateTime.now();

    if (currentDate.isAfter(taskStartDate)) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body("The start date must be greater than the current date.");
    }

    if (taskStartDate.isAfter(taskEndDate)) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body("The end date must be greater than the current date.");
    }

    TaskModel task = this.taskRepository.save(taskModel);
    return ResponseEntity.status(HttpStatus.OK).body(task);
  }

  @GetMapping("/")
  public List<TaskModel> list(HttpServletRequest request) {
    var idUser = request.getAttribute("idUser");
    List<TaskModel> tasks = this.taskRepository.findByIdUser((UUID) idUser);

    return tasks;
  }

  @PutMapping("/{idTask}")
  public ResponseEntity<?> update(@RequestBody TaskModel taskModel, HttpServletRequest request,
      @PathVariable UUID idTask) {

    var task = this.taskRepository.findById(idTask).orElse(null);

    if (task.equals(null)) {
      return ResponseEntity.badRequest().body("task not found.");
    }

    Utils.copyNonNullProperties(taskModel, task);
    return ResponseEntity.ok().body(task);
  }
}
