package cloud.moonl.sso.example;

import java.io.IOException;

import cloud.moonl.sso.spring.account.MoonSsoAccountClient;
import cloud.moonl.sso.spring.account.MoonSsoProfile;
import cloud.moonl.sso.spring.account.ProfileUpdate;
import cloud.moonl.sso.spring.core.MoonSsoException;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** Home page, profile page and profile editing through the account API. */
@Controller
class ProfileController {

	private final MoonSsoAccountClient account;

	private final RecentEvents events;

	ProfileController(MoonSsoAccountClient account, RecentEvents events) {
		this.account = account;
		this.events = events;
	}

	@GetMapping("/")
	String home(@AuthenticationPrincipal OidcUser user, Model model) {
		model.addAttribute("user", user);
		return "index";
	}

	@GetMapping("/profile")
	String profile(Model model) {
		model.addAttribute("profile", this.account.getProfile());
		model.addAttribute("events", this.events.list());
		return "profile";
	}

	/** HTMX fragment; an expired session answers 200 + HX-Redirect thanks to the starter. */
	@GetMapping("/profile/card")
	String card(Model model) {
		model.addAttribute("profile", this.account.getProfile());
		return "profile :: card";
	}

	@PostMapping("/profile")
	String update(@RequestParam String displayName, @RequestParam long version, RedirectAttributes redirect) {
		try {
			this.account.updateProfile(ProfileUpdate.displayName(displayName.trim()), version);
			redirect.addFlashAttribute("message", "资料已更新");
		}
		catch (MoonSsoException ex) {
			redirect.addFlashAttribute("error", ex.isVersionConflict() ? "资料已被其他应用修改，请刷新后重试"
					: (ex.getErrorDescription() != null ? ex.getErrorDescription() : ex.getError()));
		}
		return "redirect:/profile";
	}

	@PostMapping("/profile/avatar")
	String avatar(@RequestParam("avatar") MultipartFile file, RedirectAttributes redirect) throws IOException {
		try {
			if (file.isEmpty() || file.getContentType() == null) {
				redirect.addFlashAttribute("error", "请选择图片");
				return "redirect:/profile";
			}
			MoonSsoProfile updated = this.account.uploadAvatar(file.getBytes(),
					MediaType.parseMediaType(file.getContentType()));
			redirect.addFlashAttribute("message", "头像已更新（版本 " + updated.profileVersion() + "）");
		}
		catch (MoonSsoException | IllegalArgumentException ex) {
			redirect.addFlashAttribute("error", (ex instanceof MoonSsoException m && m.getErrorDescription() != null)
					? m.getErrorDescription() : ex.getMessage());
		}
		return "redirect:/profile";
	}

	@PostMapping("/profile/avatar/delete")
	String deleteAvatar(RedirectAttributes redirect) {
		this.account.deleteAvatar();
		redirect.addFlashAttribute("message", "头像已删除");
		return "redirect:/profile";
	}

}
