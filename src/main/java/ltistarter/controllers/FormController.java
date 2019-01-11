/**
 * Copyright 2014 Unicon (R)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ltistarter.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

/**
 * This controller should be protected by basic auth authentication (on the /basic path)
 * Username and password controlled in application.properties
 */
@Controller
@RequestMapping("/form")
public class FormController extends BaseController {

    @RequestMapping({"", "/"})
    public String home(HttpServletRequest req, Principal principal, Model model) {
        commonModelPopulate(req, principal, model);
        model.addAttribute("name", "form");
        model.addAttribute("canLogout", true);
        req.getSession().setAttribute("login", "form");
        return "home"; // name of the template
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest req) {
        log.info("login: {0} " , req);
        return "login";
    }

    // Login form with error
    @RequestMapping(value = "/login", params = "error=true")
    public String loginError(HttpServletRequest req, Model model) {
        log.info("login-error: {0} " , req);
        model.addAttribute("loginError", true);
        return "login";
    }

}
