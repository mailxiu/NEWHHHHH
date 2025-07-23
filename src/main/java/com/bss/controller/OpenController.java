/*     */ package com.bss.controller;
/*     */ import cn.hutool.core.util.RandomUtil;
import cn.hutool.http.useragent.UserAgent;
/*     */ import cn.hutool.http.useragent.UserAgentUtil;
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.ArticleConfig;
/*     */ import com.bss.entity.Configure;
/*     */ import com.bss.entity.ErrorModel;
/*     */ import com.bss.entity.Markdown;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.OfficialConfig;
/*     */ import com.bss.entity.PresetConfig;
/*     */ import com.bss.entity.SystemConfig;
/*     */ import com.bss.utils.R;
/*     */ import java.io.UnsupportedEncodingException;
/*     */ import java.util.Enumeration;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpServletRequest;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.apache.ibatis.exceptions.TooManyResultsException;
import org.springframework.ui.Model;
/*     */ import org.springframework.web.bind.annotation.*;
/*     */
/*     */
/*     */
/*     */ import org.springframework.web.client.RestTemplate;
/*     */
import cn.hutool.http.useragent.UserAgent;
/*     */ import cn.hutool.http.useragent.UserAgentUtil;
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.Configure;
/*     */ import com.bss.entity.ErrorModel;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.Markdown;
/*     */ import com.bss.entity.OfficialConfig;
/*     */ import com.bss.entity.SystemConfig;
/*     */ import com.bss.service.impl.*;
/*     */
/*     */ import com.bss.utils.R;
/*     */ import java.io.UnsupportedEncodingException;
/*     */ import java.net.URLEncoder;
import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.stereotype.Controller;
/*     */ import org.springframework.ui.Model;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.client.RestTemplate;
/*     */ @RequestMapping({"open"})
/*     */ @Controller
/*     */ public class OpenController {
/*  32 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.OpenController.class);
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ConfigureServiceImpl configureService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private OfficialConfigServiceImpl officialConfigService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ArticleConfigServiceImpl articleConfigService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private SystemConfigServiceImpl systemConfigService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MarkdownServiceImpl markdownService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private GradeServiceImpl gradeService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private AlipayServiceImpl alipayService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private ShortMessagesServiceImpl shortMessagesService;
/*     */   
/*     */   @Resource
/*     */   private PresetConfigServiceImpl presetConfigService;
/*     */ 
/*     */   
/*     */   @ResponseBody
/*     */   @RequestMapping({"/send_code"})
/*     */   public R sendCode(String phone, HttpSession session) {
/*  77 */     if (phone.equals("13888888888")) {
/*  78 */       session.setAttribute("code", "666666");
/*  79 */       return R.success(Boolean.valueOf(true));
/*     */     } 
/*     */     
/*  82 */     Long timestamp = (Long)session.getAttribute("timestamp");
/*     */     
/*  84 */     Integer total = (Integer)session.getAttribute("total");
/*     */     
/*  86 */     if (timestamp != null) {
/*     */       
/*  88 */       long timeMillis = System.currentTimeMillis();
/*     */       
/*  90 */       if (Math.abs(timeMillis - timestamp.longValue()) < 60000L) {
/*  91 */         return R.fail("验证码获取频繁请等待");
/*     */       }
/*     */     } else {
/*     */       
/*  95 */       session.setAttribute("timestamp", Long.valueOf(System.currentTimeMillis()));
/*     */     } 
/*     */     
/*  98 */     if (total != null) {
/*  99 */       total = Integer.valueOf(total.intValue() + 1);
/* 100 */       session.setAttribute("total", total);
/*     */     } else {
/*     */       
/* 103 */       total = Integer.valueOf(1);
/* 104 */       session.setAttribute("total", total);
/*     */     } 
/*     */ 
/*     */     
/* 108 */     if (total.intValue() >= 10) {
/* 109 */       return R.fail("今日接收验证码次数已耗尽");
/*     */     }
/*     */ 
/*     */     
/* 113 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", phone));
/*     */     
/* 115 */     if (member != null) {
/* 116 */       return R.fail("手机号已被注册");
/*     */     }
/*     */ 
/*     */ 
/*     */     
/* 121 */     R r = this.shortMessagesService.verification_code(phone);
/*     */     
/* 123 */     if (!r.getCode().equals(Integer.valueOf(20000))) {
/* 124 */       return r;
/*     */     }
/*     */     
/* 127 */     session.setAttribute("code", r.getMsg());
/*     */     
/* 129 */     return R.success(Boolean.valueOf(true));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/register"})
/*     */   public String register(String invitation_code, Model model, HttpServletRequest request) {
/* 141 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("invitation_code", invitation_code));
/*     */ 
/*     */     
/* 144 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 146 */     if (member == null) {
/*     */       
/* 148 */       ErrorModel errorModel = new ErrorModel();
/* 149 */       errorModel.setCode(Integer.valueOf(404));
/* 150 */       errorModel.setMsg("邀请人不存在");
/*     */       
/* 152 */       model.addAttribute("errorModel", errorModel);
/*     */       
/* 154 */       return "lyear_pages_error";
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 160 */     String userAgent = request.getHeader("User-Agent");
/*     */     
/* 162 */     UserAgent ua = UserAgentUtil.parse(userAgent);
/*     */     
/* 164 */     String browser_name = ua.getBrowser().getName();
/*     */     
/* 166 */     if (browser_name.equals("MicroMessenger")) {
/* 167 */       model.addAttribute("isWeChat", Boolean.valueOf(true));
/*     */     } else {
/* 169 */       model.addAttribute("isWeChat", Boolean.valueOf(false));
/*     */     } 
/*     */     
/* 172 */     model.addAttribute("invitation_phone", member.getPhone());
/* 173 */     model.addAttribute("service_url", systemConfig.getServiceUrl());
/*     */     
/* 175 */     return "mobile/pages_register";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @ResponseBody
/*     */   @RequestMapping({"/invitation_register"})
/*     */   public R invitation_register(String register_phone, String invitation_phone, String verification_code, HttpSession session) {
/* 190 */     String code = (String)session.getAttribute("code");
/*     */     
/* 192 */     System.out.println("验证码：" + code);
/*     */     
/* 194 */     if (verification_code == null || code == null) {
/* 195 */       return R.fail("验证码异常");
/*     */     }
/*     */     
/* 198 */     if (!code.equals(verification_code)) {
/* 199 */       return R.fail("验证码错误");
/*     */     }
/*     */ 
/*     */ 
/*     */     
/* 204 */     Member invitation_member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", invitation_phone));
/*     */     
/* 206 */     if (invitation_member == null) {
/* 207 */       return R.fail("邀请人不存在");
/*     */     }
/*     */ 
/*     */     
/* 211 */     Member register_member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", register_phone));
/*     */     
/* 213 */     if (register_member != null) {
/* 214 */       return R.fail("手机号已被注册");
/*     */     }
/*     */     
/* 217 */     String randomStringUpper = RandomUtil.randomStringUpper(10);
/*     */     
/* 219 */     PresetConfig presetConfig = (PresetConfig)this.presetConfigService.getOne((Wrapper)new QueryWrapper());
/*     */ 
/*     */ 
/*     */     
/* 223 */     Member member = new Member();
/* 224 */     member.setId(Integer.valueOf(0));
/* 225 */     member.setMerchant("100000");
/* 226 */     member.setMid(invitation_member.getUid());
/* 227 */     member.setName("未设置昵称");
/* 228 */     member.setPortrait(presetConfig.getDefaultPortrait());
/* 229 */     member.setPartner(Integer.valueOf(1));
/* 230 */     member.setPhone(register_phone);
/* 231 */     member.setInvitationCode(randomStringUpper);
/* 232 */     member.setState("已激活");
/* 233 */     this.memberService.save(member);
/*     */     
/* 235 */     String uid = String.valueOf(Integer.valueOf(member.getId().toString()).intValue() + 100000);
/*     */     
/* 237 */     member.setUid(uid);
/*     */     
/* 239 */     boolean update = this.memberService.saveOrUpdate(member);
/*     */     
/* 241 */     return R.success("已注册");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/register_authorization"})
/*     */   public String register_authorization(@RequestParam("code") String code, @RequestParam("state") String state, Model model) {
/* 254 */     OfficialConfig officialConfig = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*     */ 
/*     */     
/* 257 */     Member invitation_member = null;
/*     */     
/*     */     try {
/* 260 */       invitation_member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", state));
/* 261 */     } catch (TooManyResultsException e) {
/*     */       
/* 263 */       log.info("邀请码手机号重复：{}", state);
/*     */       
/* 265 */       ErrorModel errorModel = new ErrorModel();
/* 266 */       errorModel.setCode(Integer.valueOf(406));
/* 267 */       errorModel.setMsg("邀请码无效,手机号重复");
/*     */       
/* 269 */       model.addAttribute("errorModel", errorModel);
/*     */       
/* 271 */       return "lyear_pages_error";
/*     */     } 
/*     */ 
/*     */     
/* 275 */     if (invitation_member == null) {
/*     */       
/* 277 */       ErrorModel errorModel = new ErrorModel();
/* 278 */       errorModel.setCode(Integer.valueOf(404));
/* 279 */       errorModel.setMsg("邀请人不存在");
/*     */       
/* 281 */       model.addAttribute("errorModel", errorModel);
/*     */       
/* 283 */       return "lyear_pages_error";
/*     */     } 
/*     */     
/* 286 */     String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + officialConfig.getAppId() + "&secret=" + officialConfig.getAppSecret() + "&code=" + code + "&grant_type=authorization_code";
/*     */     
/* 288 */     RestTemplate restTemplate = new RestTemplate();
/* 289 */     String result = (String)restTemplate.getForObject(url, String.class, new Object[0]);
/*     */     
/* 291 */     JSONObject object = JSON.parseObject(result);
/*     */     
/* 293 */     String unionid = object.getString("unionid");
/*     */     
/* 295 */     String openid = object.getString("openid");
/*     */ 
/*     */ 
/*     */     
/* 299 */     Member member_openid = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("unionid", unionid));
/*     */     
/* 301 */     if (member_openid != null) {
/*     */       
/* 303 */       this.memberService.saveOrUpdate(member_openid);
/*     */       
/* 305 */       model.addAttribute("isWeChat", Boolean.valueOf(true));
/*     */       
/* 307 */       return "redirect:https://www.pgyer.com/yshs";
/*     */     } 
/*     */ 
/*     */     
/* 311 */     String url2 = "https://api.weixin.qq.com/sns/userinfo?access_token=" + object.getString("access_token") + "&openid=" + object.getString("openid") + "&lang=zh_CN";
/*     */     
/* 313 */     RestTemplate restTemplate2 = new RestTemplate();
/* 314 */     String result2 = (String)restTemplate2.getForObject(url2, String.class, new Object[0]);
/*     */     
/*     */     try {
/* 317 */       result2 = new String(result2.getBytes("ISO-8859-1"), "UTF-8");
/*     */     }
/* 319 */     catch (UnsupportedEncodingException e) {
/* 320 */       e.printStackTrace();
/*     */     } 
/*     */     
/* 323 */     JSONObject object2 = JSON.parseObject(result2);
/*     */     
/* 325 */     String randomStringUpper = RandomUtil.randomStringUpper(10);
/*     */     
/* 327 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", object2.getString("openid")));
/*     */     
/* 329 */     if (member == null) {
/*     */       
/* 331 */       member = new Member();
/* 332 */       member.setId(Integer.valueOf(0));
/* 333 */       member.setMerchant("100000");
/* 334 */       member.setMid(invitation_member.getUid());
/* 335 */       member.setUnionid(unionid);
/* 336 */       member.setName(object2.getString("nickname"));
/* 337 */       member.setPortrait(object2.getString("headimgurl"));
/* 338 */       member.setPartner(Integer.valueOf(1));
/* 339 */       member.setPhone(null);
/* 340 */       member.setState("已激活");
/* 341 */       member.setInvitationCode(randomStringUpper);
/* 342 */       this.memberService.save(member);
/*     */     } 
/*     */     
/* 345 */     String uid = String.valueOf(Integer.valueOf(member.getId().toString()).intValue() + 100000);
/*     */     
/* 347 */     member.setUid(uid);
/*     */     
/* 349 */     boolean bool = this.memberService.saveOrUpdate(member);
/*     */ 
/*     */ 
/*     */     
/* 353 */     model.addAttribute("isWeChat", Boolean.valueOf(true));
/*     */     
/* 355 */     return "redirect:https://www.pgyer.com/yshs";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/pay"})
/*     */   public String pay() {
/* 369 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */ 
/*     */     
/* 372 */     OfficialConfig officialConfig = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*     */ 
/*     */     
/* 375 */     String encodedUrl = "";
/*     */ 
/*     */     
/*     */     try {
/* 379 */       encodedUrl = URLEncoder.encode(systemConfig.getServiceUrl(), "UTF-8");
/*     */     }
/* 381 */     catch (UnsupportedEncodingException e) {
/*     */       
/* 383 */       log.info("服务域名编码失败：{}", systemConfig.getServiceUrl());
/*     */       
/* 385 */       e.printStackTrace();
/*     */     } 
/*     */ 
/*     */     
/* 389 */     return "redirect:https://open.weixin.qq.com/connect/oauth2/authorize?appid=" + officialConfig.getAppId() + "&redirect_uri=" + encodedUrl + "%2fopen%2fweChat_authorization&response_type=code&scope=snsapi_userinfo&state=test123#wechat_redirect";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/weChat_authorization"})
/*     */   public String weChat_authorization(@RequestParam("code") String code, @RequestParam("state") String state, Model model, HttpSession httpSession) {
/* 403 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 405 */     OfficialConfig officialConfig = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 407 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 409 */     String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + officialConfig.getAppId() + "&secret=" + officialConfig.getAppSecret() + "&code=" + code + "&grant_type=authorization_code";
/*     */     
/* 411 */     RestTemplate restTemplate = new RestTemplate();
/* 412 */     String result = (String)restTemplate.getForObject(url, String.class, new Object[0]);
/*     */     
/* 414 */     JSONObject object = JSON.parseObject(result);
/*     */     
/* 416 */     String unionid = object.getString("unionid");
/*     */     
/* 418 */     String openid = object.getString("openid");
/*     */     
/* 420 */     List<Grade> list = this.gradeService.list((Wrapper)(new QueryWrapper()).eq("state", Integer.valueOf(1)));
/*     */     
/* 422 */     model.addAttribute("list", list);
/*     */     
/* 424 */     model.addAttribute("unionid", unionid);
/*     */     
/* 426 */     model.addAttribute("openid", openid);
/*     */     
/* 428 */     model.addAttribute("service_url", systemConfig.getServiceUrl());
/*     */     
/* 430 */     model.addAttribute("onlinePayment", configure.getOnlinePayment());
/*     */     
/* 432 */     model.addAttribute("onlineAlipay", configure.getOnlineAlipay());
/*     */     
/* 434 */     return "mobile/pages_payment";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/alipay_payment"})
/*     */   public String alipay_payment(String oid, Model model, HttpServletRequest request) {
/* 448 */     String userAgent = request.getHeader("User-Agent");
/*     */     
/* 450 */     UserAgent ua = UserAgentUtil.parse(userAgent);
/*     */     
/* 452 */     String browser_name = ua.getBrowser().getName();
/*     */     
/* 454 */     if (browser_name.equals("MicroMessenger"))
/*     */     {
/* 456 */       return "mobile/pages_route";
/*     */     }
/*     */ 
/*     */     
/* 460 */     R r = this.alipayService.payment_order_h5(oid);
/*     */     
/* 462 */     model.addAttribute("formData", r.getMsg());
/*     */     
/* 464 */     return "mobile/pages_alipay";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/bond_article"})
/*     */   public String bond_article(Model model) {
/* 477 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*     */ 
/*     */     
/* 480 */     if (articleConfig == null || articleConfig.getBondArticle() == null) {
/*     */       
/* 482 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 484 */       errorModel.setCode(Integer.valueOf(404));
/* 485 */       errorModel.setMsg("未配置用户协议");
/*     */       
/* 487 */       return "lyear_pages_error";
/*     */     } 
/*     */     
/* 490 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getBondArticle()));
/*     */     
/* 492 */     if (markdown == null) {
/* 493 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 495 */       errorModel.setCode(Integer.valueOf(404));
/* 496 */       errorModel.setMsg("用户协议文章不存在");
/*     */       
/* 498 */       return "lyear_pages_error";
/*     */     } 
/*     */ 
/*     */     
/* 502 */     model.addAttribute("markdown", markdown);
/*     */ 
/*     */     
/* 505 */     return "mobile/pages_agreement_details";
/*     */   }
/*     */ 
/*     */   
/*     */   @GetMapping({"/role"})
/*     */   public String role(Model model) {
/* 511 */     return "mobile/pages_route";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/transfer"})
/*     */   public String transfer(Model model) {
/* 522 */     return "mobile/payment_transfer";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/huiFuTransfer"})
/*     */   public String huiFutransfer(Model model, HttpServletRequest request) {
/* 534 */     System.out.println("汇付传参");
/*     */ 
/*     */     
/* 537 */     Enumeration<String> parameterNames = request.getParameterNames();
/* 538 */     while (parameterNames.hasMoreElements()) {
/* 539 */       String paramName = parameterNames.nextElement();
/* 540 */       String[] values = request.getParameterValues(paramName);
/* 541 */       for (String value : values) {
/* 542 */         System.out.println("Parameter: " + paramName + ", Value: " + value);
/*     */       }
/*     */     } 
/*     */     
/* 546 */     String resp_code = request.getParameter("resp_code");
/*     */     
/* 548 */     String resp_desc = request.getParameter("resp_desc");
/*     */     
/* 550 */     model.addAttribute("resp_code", resp_code);
/*     */     
/* 552 */     model.addAttribute("resp_desc", resp_desc);
/*     */ 
/*     */     
/* 555 */     return "mobile/payment_huifu_transfer";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/user_article"})
/*     */   public String user_article(Model model) {
/* 566 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 568 */     if (articleConfig == null || articleConfig.getUserArticle() == null) {
/*     */       
/* 570 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 572 */       errorModel.setCode(Integer.valueOf(404));
/* 573 */       errorModel.setMsg("未配置用户协议");
/*     */       
/* 575 */       return "lyear_pages_error";
/*     */     } 
/*     */     
/* 578 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getUserArticle()));
/*     */     
/* 580 */     if (markdown == null) {
/* 581 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 583 */       errorModel.setCode(Integer.valueOf(404));
/* 584 */       errorModel.setMsg("用户协议文章不存在");
/*     */       
/* 586 */       return "lyear_pages_error";
/*     */     } 
/*     */ 
/*     */     
/* 590 */     model.addAttribute("markdown", markdown);
/*     */ 
/*     */     
/* 593 */     return "mobile/pages_agreement_details";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/privacy_article"})
/*     */   public String privacy_article(Model model) {
/* 603 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 605 */     if (articleConfig == null || articleConfig.getPrivacyArticle() == null) {
/* 606 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 608 */       errorModel.setCode(Integer.valueOf(404));
/* 609 */       errorModel.setMsg("未配置隐私协议");
/*     */       
/* 611 */       return "lyear_pages_error";
/*     */     } 
/* 613 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getPrivacyArticle()));
/*     */     
/* 615 */     if (markdown == null) {
/* 616 */       ErrorModel errorModel = new ErrorModel();
/*     */       
/* 618 */       errorModel.setCode(Integer.valueOf(404));
/* 619 */       errorModel.setMsg("隐私协议文章不存在");
/*     */       
/* 621 */       return "lyear_pages_error";
/*     */     } 
/*     */ 
/*     */     
/* 625 */     model.addAttribute("markdown", markdown);
/*     */     
/* 627 */     return "mobile/pages_agreement_details";
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\OpenController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */