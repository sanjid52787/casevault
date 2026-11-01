package uk.ac.ravensbourne.casevault.web;
import org.springframework.stereotype.Controller; import org.springframework.ui.Model; import org.springframework.web.bind.annotation.GetMapping; import org.springframework.web.bind.annotation.RequestParam;
@Controller public class LoginController { @GetMapping("/login") String login(@RequestParam(required=false) String redirect, Model model){model.addAttribute("redirect",redirect==null?"":redirect);return "login";} }
