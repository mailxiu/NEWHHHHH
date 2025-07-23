/*      */ package com.bss.controller;
/*      */ import com.alibaba.fastjson.JSONArray;
/*      */ import com.alibaba.fastjson.JSONObject;
/*      */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*      */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*      */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*      */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*      */ import com.bss.enmus.AlbumEnum;
import com.bss.entity.Category;
/*      */ import com.bss.entity.ChartCount;
/*      */ import com.bss.entity.Complaint;
/*      */ import com.bss.entity.Details;
/*      */ import com.bss.entity.Dividend;
/*      */ import com.bss.entity.Grade;
/*      */ import com.bss.entity.Markdown;
/*      */ import com.bss.entity.Member;
/*      */ import com.bss.entity.Message;
/*      */ import com.bss.entity.Notice;
/*      */ import com.bss.entity.Order;
/*      */ import com.bss.entity.PageModel;
/*      */ import com.bss.entity.Record;
/*      */ import com.bss.entity.RecordNum;
/*      */ import com.bss.entity.Settlement;
/*      */ import com.bss.entity.SystemConfig;
/*      */ import com.bss.entity.User;
/*      */ import com.bss.entity.Withdrawal;
/*      */ import java.util.HashMap;
/*      */ import java.util.List;
/*      */ import java.util.Map;
/*      */ import java.util.stream.Collectors;
/*      */ import javax.annotation.Resource;
/*      */ import javax.servlet.http.HttpSession;
/*      */ import org.apache.shiro.subject.Subject;
/*      */ import org.springframework.ui.Model;
/*      */ import org.springframework.web.bind.annotation.ModelAttribute;
/*      */ import org.springframework.web.bind.annotation.RequestMapping;
/*      */ import org.springframework.web.bind.annotation.RequestParam;
/*      */
/*      */ import com.alibaba.excel.EasyExcel;
import com.alibaba.excel.write.builder.ExcelWriterBuilder;
import com.alibaba.excel.write.builder.ExcelWriterSheetBuilder;
import com.alibaba.excel.write.handler.WriteHandler;
import com.alibaba.excel.write.style.column.LongestMatchColumnWidthStyleStrategy;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
/*      */ import com.alibaba.fastjson.JSONObject;
/*      */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*      */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*      */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*      */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*      */ import com.bss.enmus.PaymentEnum;
import com.bss.entity.*;
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */
/*      */ import java.io.OutputStream;
import java.lang.Exception;
import java.net.URLEncoder;
import java.text.NumberFormat;
import java.util.*;
import java.util.stream.Collectors;
/*      */
/*      */
/*      */ import javax.annotation.Resource;
/*      */ import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
/*      */ import com.bss.service.CategoryService;
import com.bss.service.ConfigureService;
import com.bss.service.UserService;
import com.bss.service.impl.*;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
/*      */ import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
/*      */ import org.springframework.web.bind.annotation.*;
/*      */ @Controller
/*      */ public class MainController {
/*   40 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.MainController.class);
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private CountServiceImpl countService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private OrderServiceImpl orderService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private UserService userService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private GradeServiceImpl gradeService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private RecordServiceImpl recordService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private MemberServiceImpl memberService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private ProjectServiceImpl projectService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private WithdrawalServiceImpl withdrawalService;
/*      */   
/*      */   @Resource
/*      */   private CategoryService categoryService;
/*      */   
/*      */   @Resource
/*      */   private StockServiceImpl stockService;
/*      */   
/*      */   @Resource
/*      */   private NoticeServiceImpl noticeService;
/*      */   
/*      */   @Resource
/*      */   private SettlementServiceImpl settlementService;
/*      */   
/*      */   @Resource
/*      */   private MarkdownServiceImpl markdownService;
/*      */   
/*      */   @Resource
/*      */   private ConfigureService configureService;
/*      */   
/*      */   @Resource
/*      */   private RoleServiceImpl roleService;
/*      */   
/*      */   @Resource
/*      */   private CarouselServiceImpl carouselService;
/*      */   
/*      */   @Resource
/*      */   private PosterServiceImpl posterService;
/*      */   
/*      */   @Resource
/*      */   private ScreenServiceImpl screenService;
/*      */   
/*      */   @Resource
/*      */   private AdvertiseServiceImpl advertiseService;
/*      */   
/*      */   @Resource
/*      */   private DividendServiceImpl dividendService;
/*      */   
/*      */   @Resource
/*      */   private DetailsServiceImpl detailsService;
/*      */   
/*      */   @Resource
/*      */   private MessageServiceImpl messageService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintServiceImpl complaintService;
/*      */   
/*      */   @Resource
/*      */   private PaymentConfigServiceImpl paymentConfigService;
/*      */   
/*      */   @Resource
/*      */   private PayAlipayConfigServiceImpl payAlipayConfigService;
/*      */   
/*      */   @Resource
/*      */   private AppletConfigServiceImpl appletConfigService;
/*      */   
/*      */   @Resource
/*      */   private OfficialConfigServiceImpl officialConfigService;
/*      */   
/*      */   @Resource
/*      */   private SystemConfigServiceImpl systemConfigService;
/*      */   
/*      */   @Resource
/*      */   private ArticleConfigServiceImpl articleConfigService;
/*      */   
/*      */   @Resource
/*      */   private MessageConfigServiceImpl messageConfigService;
/*      */   
/*      */   @Resource
/*      */   private PresetConfigServiceImpl presetConfigService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintItemServiceImpl complaintItemService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintReferServiceImpl complaintReferService;
/*      */   
/*      */   @Resource
/*      */   private WechatAppPayConfigServiceImpl wechatAppPayConfigService;
/*      */ 
/*      */   
/*      */   @RequestMapping({"/apple-app-site-association"})
/*      */   @ResponseBody
/*      */   public String appleAppSiteAssociation() {
/*  156 */     String str = "{\n\t\"applinks\": {\n\t\t\"apps\": [],\n\t\t\"details\": [{\n\t\t\t\"appID\": \"G2MDFVWRTW.com.union.yshs\",\n\t\t\t\"paths\": [\"/yshs/*\"]\n\t\t}]\n\t}\n}";
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/*  165 */     return str;
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping(value = {"/login"}, method = {RequestMethod.POST})
/*      */   @ResponseBody
/*      */   public String login(@RequestParam("username") String username, @RequestParam("password") String password, HttpSession session, HttpServletRequest request) {
/*  183 */     JSONObject data = new JSONObject();
/*      */     
/*  185 */     Subject currentUser = SecurityUtils.getSubject();
/*      */     
/*  187 */     UsernamePasswordToken token = new UsernamePasswordToken(username, password);
/*      */     
/*  189 */     if (!currentUser.isAuthenticated()) {
/*      */       
/*      */       try {
/*  192 */         currentUser.login((AuthenticationToken)token);
/*  193 */         QueryWrapper<User> queryWrapper = new QueryWrapper();
/*  194 */         queryWrapper.eq("username", username);
/*  195 */         User user = (User)this.userService.getOne((Wrapper)queryWrapper);
/*      */         
/*  197 */         session.setAttribute("user", user);
/*      */         
/*  199 */         data.put("state", Boolean.valueOf(true));
/*  200 */         data.put("info", "登陆成功,正在跳转首页~");
/*      */       }
/*  202 */       catch (UnknownAccountException ex) {
/*  203 */         data.put("state", Boolean.valueOf(false));
/*  204 */         data.put("info", "账户不存在");
/*  205 */       } catch (IncorrectCredentialsException ex) {
/*      */         
/*  207 */         System.out.println(ex);
/*  208 */         data.put("state", Boolean.valueOf(false));
/*  209 */         data.put("info", "密码错误");
/*  210 */       } catch (LockedAccountException ex) {
/*  211 */         data.put("state", Boolean.valueOf(false));
/*  212 */         data.put("info", "账户被锁定");
/*  213 */       } catch (AuthenticationException ex) {
/*  214 */         data.put("state", Boolean.valueOf(false));
/*  215 */         data.put("info", "非法请求,没有权限！");
/*      */       } 
/*      */     }
/*      */     
/*  219 */     return data.toString();
/*      */   }
/*      */ 
/*      */   
/*      */   @RequestMapping({"/"})
/*      */   public String page(Model model) {
/*  225 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/*  227 */     Subject currentUser = SecurityUtils.getSubject();
/*      */     
/*  229 */     if (currentUser.isAuthenticated()) {
/*  230 */       return "redirect:/index";
/*      */     }
/*      */     
/*  233 */     model.addAttribute("systemConfig", systemConfig);
/*      */     
/*  235 */     return "lyear_pages_login_2";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/login.html"})
/*      */   public String loginHtml(Model model) {
/*  242 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/*  244 */     Subject currentUser = SecurityUtils.getSubject();
/*      */     
/*  246 */     if (currentUser.isAuthenticated()) {
/*  247 */       currentUser.logout();
/*      */     }
/*      */     
/*  250 */     model.addAttribute("systemConfig", systemConfig);
/*      */     
/*  252 */     return "lyear_pages_login_2";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/logout"})
/*      */   public String logout(Model model) {
/*  259 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/*  261 */     Subject subject = SecurityUtils.getSubject();
/*  262 */     subject.logout();
/*      */     
/*  264 */     model.addAttribute("systemConfig", systemConfig);
/*      */     
/*  266 */     return "lyear_pages_login_2";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/index"})
/*      */   public String index(Model model, HttpSession session) {
/*  273 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/*  275 */     User user = (User)session.getAttribute("user");
/*      */     
/*  277 */     StringBuilder sb = new StringBuilder();
/*      */     
/*  279 */     sb.append(user.getName());
/*      */     
/*  281 */     sb.append("后台管理");
/*      */     
/*  283 */     String webSocket = systemConfig.getServiceUrl().replace("https", "wss");
/*      */ 
/*      */     
/*  286 */     if (System.getProperty("os.name").toLowerCase().contains("windows")) {
/*  287 */       webSocket = "ws://localhost:9189";
/*      */     }
/*      */     
/*  290 */     model.addAttribute("platform_name", sb.toString());
/*  291 */     model.addAttribute("systemConfig", systemConfig);
/*  292 */     model.addAttribute("sessionId", session.getId());
/*  293 */     model.addAttribute("webSocket", webSocket);
/*      */     
/*  295 */     return "index";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/main"})
/*      */   public String main(Model model, HttpSession session) {
/*  302 */     User user = (User)session.getAttribute("user");
/*      */     
/*  304 */     int records_count = this.recordService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).apply(true, "TO_DAYS(NOW())-TO_DAYS(create_time) = 0", new Object[0]));
/*      */     
/*  306 */     int increase_count = this.memberService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).apply(true, "TO_DAYS(NOW())-TO_DAYS(create_time) = 0", new Object[0]));
/*      */     
/*  308 */     int members_count = this.memberService.count((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  310 */     int withdrawals_count = this.withdrawalService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("state", "待处理"));
/*      */ 
/*      */     
/*  313 */     Map<String, Object> map = new HashMap<>();
/*      */     
/*  315 */     map.put("merchant", user.getMerchant());
/*  316 */     List<ChartCount> memberCount = this.countService.getMemberCount(map);
/*      */     
/*  318 */     List<ChartCount> recordCount = this.countService.getRecordCount(map);
/*      */ 
/*      */ 
/*      */ 
/*      */     
/*  323 */     List<String> memberCount_date = (List<String>)memberCount.stream().map(ChartCount::getTimeData).collect(Collectors.toList());
/*      */ 
/*      */ 
/*      */     
/*  327 */     List<String> memberCount_refer = (List<String>)memberCount.stream().map(ChartCount::getReferData).collect(Collectors.toList());
/*      */ 
/*      */ 
/*      */     
/*  331 */     List<String> memberCount_volume = (List<String>)memberCount.stream().map(ChartCount::getVolumeData).collect(Collectors.toList());
/*      */ 
/*      */ 
/*      */     
/*  335 */     List<String> recordCount_date = (List<String>)recordCount.stream().map(ChartCount::getTimeData).collect(Collectors.toList());
/*      */ 
/*      */ 
/*      */     
/*  339 */     List<String> recordCount_refer = (List<String>)recordCount.stream().map(ChartCount::getReferData).collect(Collectors.toList());
/*      */ 
/*      */ 
/*      */     
/*  343 */     List<String> recordCount_volume = (List<String>)recordCount.stream().map(ChartCount::getVolumeData).collect(Collectors.toList());
/*      */ 
/*      */     
/*  346 */     model.addAttribute("memberCount_date", memberCount_date);
/*  347 */     model.addAttribute("recordCount_date", recordCount_date);
/*      */     
/*  349 */     model.addAttribute("memberCount_refer", memberCount_refer);
/*  350 */     model.addAttribute("recordCount_refer", recordCount_refer);
/*      */     
/*  352 */     model.addAttribute("memberCount_volume", memberCount_volume);
/*  353 */     model.addAttribute("recordCount_volume", recordCount_volume);
/*      */ 
/*      */     
/*  356 */     model.addAttribute("records_count", Integer.valueOf(records_count));
/*  357 */     model.addAttribute("members_count", Integer.valueOf(members_count));
/*  358 */     model.addAttribute("increase_count", Integer.valueOf(increase_count));
/*  359 */     model.addAttribute("withdrawals_count", Integer.valueOf(withdrawals_count));
/*      */     
/*  361 */     return "lyear_main";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/record_list"})
/*      */   public String purchase_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String time, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String bar_code, @RequestParam(required = false, defaultValue = "") String export_state, @RequestParam(required = false, defaultValue = "审核中") String state, HttpSession session) {
/*  379 */     if (pageModel.getAction().equals("refresh")) {
/*  380 */       session.setAttribute("record_time", time);
/*  381 */       session.setAttribute("record_uid", uid);
/*  382 */       session.setAttribute("record_bar_code", bar_code);
/*  383 */       session.setAttribute("record_export_state", export_state);
/*  384 */       session.setAttribute("record_state", state);
/*      */     } else {
/*  386 */       time = (String)session.getAttribute("record_time");
/*  387 */       uid = (String)session.getAttribute("record_uid");
/*  388 */       bar_code = (String)session.getAttribute("record_bar_code");
/*  389 */       export_state = (String)session.getAttribute("record_export_state");
/*  390 */       state = (String)session.getAttribute("record_state");
/*      */     } 
/*      */     
/*  393 */     User user = (User)session.getAttribute("user");
/*      */     
/*  395 */     if (user == null) {
/*  396 */       return "lyear_pages_error";
/*      */     }
/*      */     
/*  399 */     Map<String, Object> map = new HashMap<>();
/*      */     
/*  401 */     map.put("merchant", user.getMerchant());
/*  402 */     map.put("uid", "");
/*  403 */     map.put("bar_code", bar_code);
/*  404 */     map.put("state", state);
/*      */     
/*  406 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/*      */     
/*  408 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */     
/*  410 */     if (!uid.equals("")) {
/*  411 */       queryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/*  414 */     if (!bar_code.equals("")) {
/*  415 */       queryWrapper.eq("code", bar_code);
/*      */     }
/*      */     
/*  418 */     if (!export_state.equals("")) {
/*  419 */       queryWrapper.eq("export_state", export_state);
/*      */     }
/*      */     
/*  422 */     queryWrapper.eq("sale", Integer.valueOf(1));
/*  423 */     queryWrapper.eq("state", state);
/*      */     
/*  425 */     if (!time.equals("")) {
/*  426 */       String[] split = time.split(" - ");
/*  427 */       String startTime = split[0].trim() + " 00:00:00";
/*  428 */       String endTime = split[1].trim() + " 23:59:59";
/*  429 */       queryWrapper.between("create_time", startTime, endTime);
/*      */     } 
/*      */     
/*  432 */     queryWrapper.orderByDesc("update_time");
/*      */     
/*  434 */     IPage<Record> iPage = this.recordService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  436 */     model.addAttribute("view", "record_list");
/*      */     
/*  438 */     model.addAttribute("iPage", iPage);
/*      */     
/*  440 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/*  442 */     return "pages_record_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/record_export"})
/*      */   public String record_export(Model model, HttpSession session) {
/*  455 */     User user = (User)session.getAttribute("user");
/*      */     
/*  457 */     Map<String, Object> map = new HashMap<>();
/*      */     
/*  459 */     map.put("merchant", user.getMerchant());
/*  460 */     map.put("sale", Integer.valueOf(1));
/*  461 */     map.put("state", "审核中");
/*      */     
/*  463 */     List<RecordNum> list = this.countService.getCount(map);
/*      */     
/*  465 */     model.addAttribute("list", list);
/*      */     
/*  467 */     return "pages_record_export";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/record_verify"})
/*      */   public String record_verify(Model model, HttpSession session) {
/*  479 */     User user = (User)session.getAttribute("user");
/*      */     
/*  481 */     Map<String, Object> map = new HashMap<>();
/*      */     
/*  483 */     map.put("merchant", user.getMerchant());
/*      */     
/*  485 */     List<StockNum> list = this.countService.stockCount(map);
/*      */     
/*  487 */     model.addAttribute("list", list);
/*      */     
/*  489 */     return "pages_record_verify";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/stock_list"})
/*      */   public String stock_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String bar_code, @RequestParam(required = false, defaultValue = "") String uid, HttpSession session) {
/*  500 */     User user = (User)session.getAttribute("user");
/*      */     
/*  502 */     if (user == null) {
/*  503 */       return "lyear_pages_error";
/*      */     }
/*      */     
/*  506 */     if (pageModel.getAction().equals("refresh")) {
/*  507 */       session.setAttribute("stock_bar_code", bar_code);
/*  508 */       session.setAttribute("stock_uid", uid);
/*      */     } else {
/*  510 */       bar_code = (String)session.getAttribute("stock_bar_code");
/*  511 */       uid = (String)session.getAttribute("stock_uid");
/*      */     } 
/*      */     
/*  514 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/*      */     
/*  516 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */     
/*  518 */     if (!uid.equals("")) {
/*  519 */       queryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/*  522 */     if (!bar_code.equals("")) {
/*  523 */       queryWrapper.eq("code", bar_code);
/*      */     }
/*      */     
/*  526 */     queryWrapper.eq("sale", Integer.valueOf(0));
/*  527 */     queryWrapper.eq("state", "审核中");
/*  528 */     queryWrapper.orderByDesc("create_time");
/*      */     
/*  530 */     IPage<Record> iPage = this.recordService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  532 */     model.addAttribute("view", "stock_list");
/*      */     
/*  534 */     model.addAttribute("iPage", iPage);
/*      */     
/*  536 */     model.addAttribute("list", iPage.getRecords());
/*      */ 
/*      */     
/*  539 */     return "pages_stock_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/message_list"})
/*      */   public String message_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String state, HttpSession session) {
/*  553 */     if (pageModel.getAction().equals("refresh")) {
/*  554 */       session.setAttribute("message_uid", uid);
/*  555 */       session.setAttribute("message_state", state);
/*      */     } else {
/*  557 */       uid = (String)session.getAttribute("message_uid");
/*  558 */       state = (String)session.getAttribute("message_state");
/*      */     } 
/*      */     
/*  561 */     QueryWrapper<Message> queryWrapper = new QueryWrapper();
/*      */     
/*  563 */     if (!uid.equals("")) {
/*  564 */       queryWrapper.eq("uid", uid);
/*      */     }
/*  566 */     if (!state.equals("")) {
/*  567 */       queryWrapper.eq("state", state);
/*      */     }
/*      */     
/*  570 */     queryWrapper.orderByDesc("create_time");
/*      */     
/*  572 */     IPage<Message> iPage = this.messageService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  574 */     model.addAttribute("view", "message_list");
/*      */     
/*  576 */     model.addAttribute("iPage", iPage);
/*      */     
/*  578 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/*  580 */     return "pages_message_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/category_add"})
/*      */   public String category_add() {
/*  591 */     return "pages_category_add";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/category_update"})
/*      */   public String category_update(Model model, Integer id) {
/*  601 */     Category category = (Category)this.categoryService.getById(id);
/*      */     
/*  603 */     model.addAttribute("category", category);
/*      */     
/*  605 */     return "pages_category_update";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/category_list"})
/*      */   public String category_list(Model model, @RequestParam(required = false, defaultValue = "1") int pageIndex, HttpSession session) {
/*  614 */     User user = (User)session.getAttribute("user");
/*      */     
/*  616 */     Page<Category> iPage = (Page<Category>)this.categoryService.page((IPage)new Page(pageIndex, 12L), (Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  618 */     List<Category> categoryList = iPage.getRecords();
/*      */     
/*  620 */     JSONArray list = (JSONArray)JSON.toJSON(categoryList);
/*      */     
/*  622 */     for (int i = 0; i < categoryList.size(); i++) {
/*      */       
/*  624 */       JSONObject t = list.getJSONObject(i);
/*  625 */       int count = this.projectService.count((Wrapper)(new QueryWrapper()).eq("cid", ((Category)categoryList.get(i)).getId()));
/*  626 */       t.put("count", Integer.valueOf(count));
/*      */     } 
/*      */     
/*  629 */     model.addAttribute("iPage", iPage);
/*      */     
/*  631 */     model.addAttribute("list", list);
/*      */     
/*  633 */     return "pages_category_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/exchange_list"})
/*      */   public String exchange_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String time, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "待处理") String state, HttpSession session) {
/*  645 */     if (pageModel.getAction().equals("refresh")) {
/*  646 */       session.setAttribute("exchange_time", time);
/*  647 */       session.setAttribute("exchange_uid", uid);
/*  648 */       session.setAttribute("exchange_state", state);
/*      */     } else {
/*  650 */       time = (String)session.getAttribute("exchange_time");
/*  651 */       uid = (String)session.getAttribute("exchange_uid");
/*  652 */       state = (String)session.getAttribute("exchange_state");
/*      */     } 
/*      */     
/*  655 */     User user = (User)session.getAttribute("user");
/*      */     
/*  657 */     if (user == null) {
/*  658 */       return "lyear_pages_error";
/*      */     }
/*      */     
/*  661 */     QueryWrapper<Withdrawal> queryWrapper = new QueryWrapper();
/*  662 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */ 
/*      */     
/*  665 */     if (!uid.equals("")) {
/*  666 */       queryWrapper.eq("uid", uid);
/*      */     }
/*  668 */     if (!state.equals("")) {
/*  669 */       queryWrapper.eq("state", state);
/*      */     }
/*      */     
/*  672 */     if (!time.equals("")) {
/*  673 */       String[] split = time.split(" - ");
/*  674 */       String startTime = split[0].trim() + " 00:00:00";
/*  675 */       String endTime = split[1].trim() + " 23:59:59";
/*  676 */       queryWrapper.between("create_time", startTime, endTime);
/*      */     } 
/*      */     
/*  679 */     queryWrapper.orderByDesc("create_time");
/*      */     
/*  681 */     IPage<Withdrawal> iPage = this.withdrawalService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  683 */     model.addAttribute("view", "exchange_list");
/*      */     
/*  685 */     model.addAttribute("iPage", iPage);
/*      */     
/*  687 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/*  689 */     return "pages_exchange_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/withdrawal_details"})
/*      */   public String withdrawal_details(String uid, Model model, HttpSession session) {
/*  698 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */ 
/*      */     
/*  701 */     model.addAttribute("member", member);
/*      */     
/*  703 */     return "pages_withdrawal_details";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/exchange_config"})
/*      */   public String withdrawal_config(Model model, HttpSession session) {
/*  716 */     User user = (User)session.getAttribute("user");
/*      */     
/*  718 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  720 */     model.addAttribute("configure", configure);
/*      */     
/*  722 */     return "pages_exchange_config";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/grade_update"})
/*      */   public String grade_update(Integer id, Model model, HttpSession session) {
/*  731 */     User user = (User)session.getAttribute("user");
/*      */     
/*  733 */     Grade grade = new Grade();
/*      */     
/*  735 */     if (id.intValue() == 0) {
/*  736 */       grade.setId(Integer.valueOf(0));
/*  737 */       grade.setMerchant(user.getMerchant());
/*      */     } else {
/*  739 */       grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("id", id)).eq("merchant", user.getMerchant()));
/*      */     } 
/*      */     
/*  742 */     model.addAttribute("grade", grade);
/*      */     
/*  744 */     return "pages_grade_update";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/grade_list"})
/*      */   public String grade_list(Model model, HttpSession session) {
/*  752 */     User user = (User)session.getAttribute("user");
/*      */     
/*  754 */     List<Grade> list = this.gradeService.list((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  756 */     model.addAttribute("list", list);
/*      */     
/*  758 */     return "pages_grade_list";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/project_add"})
/*      */   public String project_add(Model model, HttpSession session) {
/*  765 */     User user = (User)session.getAttribute("user");
/*      */     
/*  767 */     List<Category> list = this.categoryService.list((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  769 */     model.addAttribute("list", list);
/*      */     
/*  771 */     return "pages_project_add";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/project_update"})
/*      */   public String project_update(Integer id, Model model, HttpSession session) {
/*  778 */     User user = (User)session.getAttribute("user");
/*      */     
/*  780 */     Project project = (Project)this.projectService.getById(id);
/*      */     
/*  782 */     List<Category> list = this.categoryService.list((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  784 */     model.addAttribute("project", project);
/*      */     
/*  786 */     model.addAttribute("list", list);
/*      */ 
/*      */     
/*  789 */     return "pages_project_update";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/project_details"})
/*      */   public String project_details(Integer id, Model model) {
/*  802 */     Details details = (Details)this.detailsService.getOne((Wrapper)(new QueryWrapper()).eq("pid", id));
/*      */     
/*  804 */     if (details == null) {
/*  805 */       details = new Details();
/*  806 */       details.setId(Integer.valueOf(0));
/*  807 */       details.setMd("未配置");
/*      */     } 
/*      */     
/*  810 */     model.addAttribute("pid", id);
/*      */     
/*  812 */     model.addAttribute("details", details);
/*      */     
/*  814 */     return "pages_project_details";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/project_list"})
/*      */   public String project_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String bar_code, @RequestParam(required = false, defaultValue = "0") String cid, @RequestParam(required = false, defaultValue = "") String state, HttpSession session) {
/*  828 */     if (pageModel.getAction().equals("refresh")) {
/*  829 */       session.setAttribute("project_bar_code", bar_code);
/*  830 */       session.setAttribute("project_cid", cid);
/*  831 */       session.setAttribute("project_state", state);
/*      */     } else {
/*  833 */       bar_code = (String)session.getAttribute("project_bar_code");
/*  834 */       cid = (String)session.getAttribute("project_cid");
/*  835 */       state = (String)session.getAttribute("project_state");
/*      */     } 
/*      */     
/*  838 */     User user = (User)session.getAttribute("user");
/*      */     
/*  840 */     if (user == null) {
/*  841 */       return "lyear_pages_error";
/*      */     }
/*      */     
/*  844 */     QueryWrapper queryWrapper = new QueryWrapper();
/*  845 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */     
/*  847 */     if (!cid.equals("0")) {
/*  848 */       queryWrapper.eq("cid", cid);
/*      */     }
/*  850 */     if (!bar_code.equals("")) {
/*  851 */       queryWrapper.eq("bar_code", bar_code);
/*      */     }
/*      */     
/*  854 */     if (!state.equals("")) {
/*  855 */       queryWrapper.eq("state", state);
/*      */     }
/*      */ 
/*      */     
/*  859 */     List<String> stateList = this.projectService.stateList(user.getMerchant());
/*      */     
/*  861 */     List<Category> categoryList = this.categoryService.list((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/*  863 */     IPage<Project> iPage = this.projectService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  865 */     model.addAttribute("view", "project_list");
/*      */     
/*  867 */     model.addAttribute("stateList", stateList);
/*  868 */     model.addAttribute("categoryList", categoryList);
/*      */     
/*  870 */     model.addAttribute("iPage", iPage);
/*      */     
/*  872 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/*  874 */     return "pages_project_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/complaint_list"})
/*      */   public String complaint_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String state, HttpSession session) {
/*  894 */     if (pageModel.getAction().equals("refresh")) {
/*  895 */       session.setAttribute("complaint_uid", uid);
/*  896 */       session.setAttribute("complaint_state", state);
/*      */     } else {
/*  898 */       uid = (String)session.getAttribute("complaint_uid");
/*  899 */       state = (String)session.getAttribute("complaint_state");
/*      */     } 
/*      */     
/*  902 */     User user = (User)session.getAttribute("user");
/*      */     
/*  904 */     if (user == null) {
/*  905 */       return "lyear_pages_error";
/*      */     }
/*      */ 
/*      */     
/*  909 */     QueryWrapper queryWrapper = new QueryWrapper();
/*      */ 
/*      */     
/*  912 */     if (!uid.equals("")) {
/*  913 */       queryWrapper.eq("complaint_uid", uid);
/*      */     }
/*      */     
/*  916 */     if (!state.equals("")) {
/*  917 */       queryWrapper.eq("state", state);
/*      */     }
/*      */ 
/*      */     
/*  921 */     IPage<Complaint> iPage = this.complaintService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/*  923 */     model.addAttribute("view", "complaint_list");
/*      */     
/*  925 */     model.addAttribute("iPage", iPage);
/*      */     
/*  927 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/*  929 */     return "pages_complaint_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/complaint_details"})
/*      */   public String complaint_details(String oid, Model model, HttpSession session) {
/*  945 */     Complaint complaint = (Complaint)this.complaintService.getOne((Wrapper)(new QueryWrapper()).eq("complaint_number", oid));
/*      */ 
/*      */     
/*  948 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", complaint.getComplaintUid()));
/*      */ 
/*      */ 
/*      */     
/*  952 */     List<ComplaintItem> itemList = this.complaintItemService.list((Wrapper)(new QueryWrapper()).eq("complaint_number", oid));
/*      */ 
/*      */     
/*  955 */     JSONArray itemsJson = JSONArray.parseArray(JSON.toJSONString(itemList));
/*      */     
/*  957 */     for (int i = 0; i < itemsJson.size(); i++) {
/*      */       
/*  959 */       JSONObject jsonObject = itemsJson.getJSONObject(i);
/*      */       
/*  961 */       String images = jsonObject.getString("images");
/*      */       
/*  963 */       if (images.length() < 6) {
/*  964 */         jsonObject.put("images", new String[0]);
/*      */       } else {
/*  966 */         String[] split = images.split(",");
/*      */         
/*  968 */         jsonObject.put("images", split);
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/*  973 */     model.addAttribute("complaint", complaint);
/*      */     
/*  975 */     model.addAttribute("itemList", itemsJson);
/*      */     
/*  977 */     model.addAttribute("member", member);
/*      */     
/*  979 */     return "pages_complaint_details";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/complaint_refer"})
/*      */   public String complaint_refer(@ModelAttribute PageModel pageModel, Model model, HttpSession session) {
/*  994 */     IPage<ComplaintRefer> iPage = this.complaintReferService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()));
/*      */     
/*  996 */     model.addAttribute("iPage", iPage);
/*      */     
/*  998 */     model.addAttribute("view", "complaint_refer");
/*      */     
/* 1000 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1002 */     return "pages_complaint_refer";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/member_update"})
/*      */   public String member_update(String uid, Model model) {
/* 1015 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/* 1017 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */     
/* 1019 */     model.addAttribute("member", member);
/*      */     
/* 1021 */     model.addAttribute("grade", grade);
/*      */     
/* 1023 */     return "pages_member_update";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/user_list"})
/*      */   public String user_list(Model model, @RequestParam(required = false, defaultValue = "1") int pageIndex, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String partner, @RequestParam(required = false, defaultValue = "refresh") String action, HttpSession session) {
/* 1037 */     if (action.equals("refresh")) {
/* 1038 */       session.setAttribute("member_uid", uid);
/* 1039 */       session.setAttribute("member_partner", partner);
/*      */     } else {
/* 1041 */       uid = (String)session.getAttribute("member_uid");
/* 1042 */       partner = (String)session.getAttribute("member_partner");
/*      */     } 
/*      */     
/* 1045 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1047 */     if (user == null) {
/* 1048 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1051 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1053 */     map.put("merchant", user.getMerchant());
/*      */     
/* 1055 */     map.put("uid", uid);
/*      */     
/* 1057 */     map.put("partner", partner);
/*      */     
/* 1059 */     IPage<User> iPage = this.userService.page((IPage)new Page(pageIndex, 12L));
/*      */     
/* 1061 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1063 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1065 */     return "pages_user_list";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/role_list"})
/*      */   public String role_list(Model model, HttpSession session) {
/* 1072 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1074 */     if (user == null) {
/* 1075 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1078 */     IPage<Role> iPage = this.roleService.page((IPage)new Page(1L, 12L));
/*      */     
/* 1080 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1082 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1084 */     return "pages_role_list";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/permission_list"})
/*      */   public String permission_list(Model model, HttpSession session) {
/* 1091 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1093 */     if (user == null) {
/* 1094 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1097 */     IPage<Role> iPage = this.roleService.page((IPage)new Page(1L, 12L));
/*      */     
/* 1099 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1101 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1103 */     return "pages_permission_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/order_list"})
/*      */   public String order_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String time, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String payment_type, @RequestParam(required = false, defaultValue = "") String state, HttpSession session) {
/* 1117 */     if (pageModel.getAction().equals("refresh")) {
/* 1118 */       session.setAttribute("order_time", time);
/* 1119 */       session.setAttribute("order_uid", uid);
/* 1120 */       session.setAttribute("order_payment_type", payment_type);
/* 1121 */       session.setAttribute("order_state", state);
/*      */     } else {
/* 1123 */       time = (String)session.getAttribute("order_time");
/* 1124 */       uid = (String)session.getAttribute("order_uid");
/* 1125 */       payment_type = (String)session.getAttribute("order_payment_type");
/* 1126 */       state = (String)session.getAttribute("order_state");
/*      */     } 
/*      */     
/* 1129 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1131 */     if (user == null) {
/* 1132 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1135 */     QueryWrapper<Order> queryWrapper = new QueryWrapper();
/*      */     
/* 1137 */     if (!uid.equals("")) {
/* 1138 */       queryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/* 1141 */     if (!payment_type.equals("")) {
/* 1142 */       queryWrapper.eq("payment_type", payment_type);
/*      */     }
/*      */     
/* 1145 */     if (!state.equals("")) {
/* 1146 */       queryWrapper.eq("state", state);
/*      */     }
/*      */     
/* 1149 */     if (!time.equals("")) {
/* 1150 */       String[] split = time.split(" - ");
/* 1151 */       String startTime = split[0].trim() + " 00:00:00";
/* 1152 */       String endTime = split[1].trim() + " 23:59:59";
/* 1153 */       queryWrapper.between("create_time", startTime, endTime);
/*      */     } 
/*      */     
/* 1156 */     queryWrapper.orderByDesc("create_time");
/*      */     
/* 1158 */     IPage<Order> iPage = this.orderService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/* 1160 */     model.addAttribute("view", "order_list");
/*      */     
/* 1162 */     model.addAttribute("paymentEnum", PaymentEnum.values());
/*      */     
/* 1164 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1166 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1168 */     return "pages_order_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/settlement_list"})
/*      */   public String settlement_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String time, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String type, HttpSession session) {
/* 1180 */     if (pageModel.getAction().equals("refresh")) {
/* 1181 */       session.setAttribute("settlement_time", time);
/* 1182 */       session.setAttribute("settlement_uid", uid);
/* 1183 */       session.setAttribute("settlement_type", type);
/*      */     } else {
/* 1185 */       time = (String)session.getAttribute("settlement_time");
/* 1186 */       uid = (String)session.getAttribute("settlement_uid");
/* 1187 */       type = (String)session.getAttribute("settlement_type");
/*      */     } 
/*      */     
/* 1190 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1192 */     if (user == null) {
/* 1193 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1196 */     QueryWrapper<Settlement> queryWrapper = new QueryWrapper();
/*      */     
/* 1198 */     queryWrapper.orderByDesc("create_time");
/*      */     
/* 1200 */     if (!uid.equals("")) {
/* 1201 */       queryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/* 1204 */     if (!type.equals("")) {
/* 1205 */       queryWrapper.eq("type", type);
/*      */     }
/*      */     
/* 1208 */     if (!time.equals("")) {
/* 1209 */       String[] split = time.split(" - ");
/* 1210 */       String startTime = split[0].trim() + " 00:00:00";
/* 1211 */       String endTime = split[1].trim() + " 23:59:59";
/* 1212 */       queryWrapper.between("create_time", startTime, endTime);
/*      */     } 
/*      */     
/* 1215 */     List<Settlement> type_list = this.settlementService.list((Wrapper)(new QueryWrapper()).groupBy("type"));
/*      */     
/* 1217 */     IPage<Settlement> iPage = this.settlementService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/* 1219 */     model.addAttribute("view", "settlement_list");
/*      */     
/* 1221 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1223 */     model.addAttribute("type_list", type_list);
/*      */     
/* 1225 */     model.addAttribute("list", iPage.getRecords());
/*      */ 
/*      */ 
/*      */     
/* 1229 */     return "pages_settlement_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/member_list"})
/*      */   public String member_list(Model model, @ModelAttribute PageModel pageModel, @RequestParam(required = false, defaultValue = "") String time, @RequestParam(required = false, defaultValue = "") String uid, @RequestParam(required = false, defaultValue = "") String mid, @RequestParam(required = false, defaultValue = "") String phone, @RequestParam(required = false, defaultValue = "") String partner, HttpSession session) {
/* 1244 */     if (pageModel.getAction().equals("refresh")) {
/* 1245 */       session.setAttribute("member_time", time);
/* 1246 */       session.setAttribute("member_uid", uid);
/* 1247 */       session.setAttribute("member_mid", mid);
/* 1248 */       session.setAttribute("member_phone", phone);
/* 1249 */       session.setAttribute("member_partner", partner);
/*      */     } else {
/* 1251 */       time = (String)session.getAttribute("member_time");
/* 1252 */       uid = (String)session.getAttribute("member_uid");
/* 1253 */       mid = (String)session.getAttribute("member_mid");
/* 1254 */       phone = (String)session.getAttribute("member_phone");
/* 1255 */       partner = (String)session.getAttribute("member_partner");
/*      */     } 
/*      */ 
/*      */ 
/*      */     
/* 1260 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1262 */     if (user == null) {
/* 1263 */       return "lyear_pages_error";
/*      */     }
/*      */     
/* 1266 */     QueryWrapper<Member> queryWrapper = new QueryWrapper();
/*      */     
/* 1268 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */     
/* 1270 */     queryWrapper.orderByDesc("create_time");
/*      */     
/* 1272 */     if (!uid.equals("")) {
/* 1273 */       queryWrapper.eq("uid", uid);
/*      */     }
/*      */     
/* 1276 */     if (!mid.equals("")) {
/* 1277 */       queryWrapper.eq("mid", mid);
/*      */     }
/*      */     
/* 1280 */     if (!phone.equals("")) {
/* 1281 */       queryWrapper.eq("phone", phone);
/*      */     }
/*      */     
/* 1284 */     if (!partner.equals("")) {
/* 1285 */       queryWrapper.eq("partner", partner);
/*      */     }
/*      */     
/* 1288 */     if (!time.equals("")) {
/* 1289 */       String[] split = time.split(" - ");
/* 1290 */       String startTime = split[0].trim() + " 00:00:00";
/* 1291 */       String endTime = split[1].trim() + " 23:59:59";
/* 1292 */       queryWrapper.between("create_time", startTime, endTime);
/*      */     } 
/*      */ 
/*      */     
/* 1296 */     List<Grade> gradeList = this.gradeService.list((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/* 1298 */     IPage<Member> iPage = this.memberService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/* 1300 */     model.addAttribute("view", "member_list");
/*      */     
/* 1302 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1304 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1306 */     model.addAttribute("gradeList", gradeList);
/*      */     
/* 1308 */     return "pages_member_list";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/member_details"})
/*      */   public String member_details(String uid, Model model, HttpSession session) {
/* 1315 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1317 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/* 1319 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("sort", member.getPartner()));
/*      */ 
/*      */     
/* 1322 */     int all_num = this.recordService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", member.getUid()));
/* 1323 */     int examine_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", uid)).eq("state", "审核中"));
/* 1324 */     int adopt_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", uid)).eq("state", "已通过"));
/* 1325 */     int failed_num = this.recordService.count((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("uid", uid)).eq("state", "未通过"));
/*      */     
/* 1327 */     int spread_num = this.memberService.count((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).eq("mid", uid));
/*      */ 
/*      */     
/* 1330 */     Map<String, Object> whole_map = this.settlementService.getMap((Wrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(total),0) as points" }).eq("uid", uid));
/* 1331 */     Map<String, Object> recovery_map = this.settlementService.getMap((Wrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(total),0) as points" }).eq("uid", uid)).eq("type", "回收结算"));
/* 1332 */     Map<String, Object> upgrade_map = this.settlementService.getMap((Wrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(total),0) as points" }).eq("uid", uid)).eq("type", "升级分佣"));
/* 1333 */     Map<String, Object> present_map = this.settlementService.getMap((Wrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(total),0) as points" }).eq("uid", uid)).eq("type", "卖货提成"));
/*      */     
/* 1335 */     Map<String, Object> finished_map = this.withdrawalService.getMap((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(points),0) as points" }).eq("merchant", user.getMerchant())).eq("uid", uid)).eq("state", "已处理"));
/* 1336 */     Map<String, Object> pending_map = this.withdrawalService.getMap((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(points),0) as points" }).eq("merchant", user.getMerchant())).eq("uid", uid)).eq("state", "待处理"));
/*      */     
/* 1338 */     Map<String, Object> record_map = this.recordService.getMap((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).select(new String[] { "IFNULL(sum(points),0) as points" }).eq("merchant", user.getMerchant())).eq("uid", member.getUid())).eq("state", "已通过"));
/*      */     
/* 1340 */     Map<String, Object> countMap = new HashMap<>();
/*      */     
/* 1342 */     countMap.put("merchant", user.getMerchant());
/* 1343 */     countMap.put("uid", uid);
/*      */     
/* 1345 */     List<RecordCount> recordCountList = this.countService.getCountByUid(countMap);
/*      */ 
/*      */     
/* 1348 */     int sum = adopt_num + failed_num;
/*      */     
/* 1350 */     double d1 = adopt_num * 1.0D;
/* 1351 */     double d2 = sum * 1.0D;
/* 1352 */     NumberFormat percentInstance = NumberFormat.getPercentInstance();
/*      */     
/* 1354 */     percentInstance.setMinimumFractionDigits(2);
/*      */     
/* 1356 */     String credit = "";
/*      */     
/* 1358 */     if (sum != 0 && failed_num != 0 && failed_num != 0) {
/* 1359 */       credit = percentInstance.format(d1 / d2);
/*      */     } else {
/* 1361 */       credit = "计算中";
/*      */     } 
/*      */     
/* 1364 */     model.addAttribute("member", member);
/*      */     
/* 1366 */     model.addAttribute("record_sum", record_map.get("points"));
/*      */     
/* 1368 */     model.addAttribute("finished_sum", finished_map.get("points"));
/* 1369 */     model.addAttribute("pending_sum", pending_map.get("points"));
/* 1370 */     model.addAttribute("whole_sum", whole_map.get("points"));
/* 1371 */     model.addAttribute("recovery_sum", recovery_map.get("points"));
/* 1372 */     model.addAttribute("upgrade_sum", upgrade_map.get("points"));
/* 1373 */     model.addAttribute("present_sum", present_map.get("points"));
/* 1374 */     model.addAttribute("all_num", Integer.valueOf(all_num));
/* 1375 */     model.addAttribute("examine_num", Integer.valueOf(examine_num));
/* 1376 */     model.addAttribute("adopt_num", Integer.valueOf(adopt_num));
/* 1377 */     model.addAttribute("failed_num", Integer.valueOf(failed_num));
/* 1378 */     model.addAttribute("credit", credit);
/* 1379 */     model.addAttribute("spread_num", Integer.valueOf(spread_num));
/* 1380 */     model.addAttribute("project_num", Integer.valueOf(recordCountList.size()));
/* 1381 */     model.addAttribute("grade", grade);
/* 1382 */     model.addAttribute("list", recordCountList);
/*      */     
/* 1384 */     return "pages_member_details";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/member_spread"})
/*      */   public String member_spread(String uid, @RequestParam(required = false, defaultValue = "") String partner, @RequestParam(required = false, defaultValue = "direct") String relation, Model model, HttpSession session) {
/* 1395 */     session.setAttribute("details_partner", partner);
/*      */     
/* 1397 */     session.setAttribute("details_relation", relation);
/*      */     
/* 1399 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/* 1401 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */ 
/*      */     
/* 1404 */     if (relation.equals("direct")) {
/*      */       
/* 1406 */       QueryWrapper<Member> queryWrapper = (QueryWrapper<Member>)(new QueryWrapper()).eq("mid", Long.valueOf(uid));
/*      */       
/* 1408 */       if (!partner.equals("")) {
/* 1409 */         queryWrapper.eq("partner", partner);
/*      */       }
/*      */       
/* 1412 */       List<Member> list = this.memberService.list((Wrapper)queryWrapper);
/*      */       
/* 1414 */       model.addAttribute("list", list);
/*      */     }
/* 1416 */     else if (relation.equals("indirect")) {
/*      */ 
/*      */       
/* 1419 */       List<Member> members = this.memberService.list((Wrapper)(new QueryWrapper()).eq("mid", Long.valueOf(uid)));
/*      */ 
/*      */ 
/*      */ 
/*      */       
/* 1424 */       String[] uidArray = (String[])members.stream().map(Member::getUid).toArray(x$0 -> new String[x$0]);
/*      */       
/* 1426 */       if (members.size() >= 1) {
/* 1427 */         QueryWrapper<Member> queryWrapper = (QueryWrapper<Member>)(new QueryWrapper()).in("mid", (Object[])uidArray);
/*      */         
/* 1429 */         if (!partner.equals("")) {
/* 1430 */           queryWrapper.eq("partner", partner);
/*      */         }
/*      */         
/* 1433 */         List<Member> list = this.memberService.list((Wrapper)queryWrapper);
/*      */         
/* 1435 */         model.addAttribute("list", list);
/*      */       } else {
/* 1437 */         model.addAttribute("list", new ArrayList());
/*      */       } 
/*      */     } 
/*      */ 
/*      */     
/* 1442 */     List<Grade> gradeList = this.gradeService.list((Wrapper)(new QueryWrapper()).orderByDesc("sort"));
/*      */     
/* 1444 */     model.addAttribute("gradeList", gradeList);
/*      */     
/* 1446 */     model.addAttribute("member", member);
/*      */     
/* 1448 */     model.addAttribute("grade", grade);
/*      */     
/* 1450 */     return "pages_member_spread";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/dividend_update"})
/*      */   public String dividend_update(Model model, @RequestParam(required = false, defaultValue = "0") Integer id) {
/* 1463 */     Dividend dividend = new Dividend();
/*      */     
/* 1465 */     if (id.intValue() == 0) {
/* 1466 */       dividend.setId(Integer.valueOf(0));
/*      */     } else {
/* 1468 */       dividend = (Dividend)this.dividendService.getOne((Wrapper)(new QueryWrapper()).eq("id", id));
/*      */     } 
/*      */     
/* 1471 */     model.addAttribute("dividend", dividend);
/*      */     
/* 1473 */     return "pages_dividend_update";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/dividend_list"})
/*      */   public String dividend_list(Model model, HttpSession session) {
/* 1486 */     List<Dividend> list = this.dividendService.list((Wrapper)new QueryWrapper());
/*      */     
/* 1488 */     model.addAttribute("list", list);
/*      */     
/* 1490 */     return "pages_dividend_list";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/notice_add"})
/*      */   public String notice_add(Model model, HttpSession session) {
/* 1497 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1499 */     Notice notice = (Notice)this.noticeService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/* 1501 */     if (notice == null) {
/*      */       
/* 1503 */       notice = new Notice();
/* 1504 */       notice.setId(Integer.valueOf(0));
/* 1505 */       notice.setMerchant(user.getMerchant());
/* 1506 */       notice.setInfo("未设置..");
/* 1507 */       notice.setSpeed(Integer.valueOf(70));
/*      */       
/* 1509 */       this.noticeService.save(notice);
/*      */     } 
/*      */ 
/*      */     
/* 1513 */     model.addAttribute("notice", notice);
/*      */     
/* 1515 */     return "pages_notice_add";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/markdown_add"})
/*      */   public String markdown_add(Model model) {
/* 1522 */     model.addAttribute("albumEnum", AlbumEnum.values());
/*      */     
/* 1524 */     return "pages_markdown_add";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/markdown_update"})
/*      */   public String markdown_update(Integer id, Model model) {
/* 1531 */     Markdown markdown = (Markdown)this.markdownService.getById(id);
/*      */     
/* 1533 */     model.addAttribute("markdown", markdown);
/*      */     
/* 1535 */     model.addAttribute("albumEnum", AlbumEnum.values());
/*      */ 
/*      */     
/* 1538 */     return "pages_markdown_update";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/markdown_details"})
/*      */   public String markdown_details(Integer id, Model model) {
/* 1545 */     Markdown markdown = (Markdown)this.markdownService.getById(id);
/*      */     
/* 1547 */     model.addAttribute("markdown", markdown);
/*      */     
/* 1549 */     return "pages_markdown_details";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/markdown_list"})
/*      */   public String markdown_list(Model model, @ModelAttribute PageModel pageModel) {
/* 1558 */     Page<Markdown> iPage = (Page<Markdown>)this.markdownService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)(new QueryWrapper()).orderByDesc("sort"));
/*      */     
/* 1560 */     model.addAttribute("view", "markdown_list");
/* 1561 */     model.addAttribute("list", iPage.getRecords());
/* 1562 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1564 */     return "pages_markdown_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/carousel_list"})
/*      */   public String carousel_list(Model model, @ModelAttribute PageModel pageModel, HttpSession session) {
/* 1573 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1575 */     Page<Carousel> iPage = (Page<Carousel>)this.carouselService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", user.getMerchant())).orderByDesc("sort"));
/*      */     
/* 1577 */     model.addAttribute("view", "carousel_list");
/* 1578 */     model.addAttribute("list", iPage.getRecords());
/* 1579 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1581 */     return "pages_carousel_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/advertise_edit"})
/*      */   public String advertise_edit(Model model, HttpSession session) {
/* 1589 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1591 */     Advertise advertise = (Advertise)this.advertiseService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/* 1593 */     model.addAttribute("advertise", advertise);
/*      */     
/* 1595 */     return "pages_advertise_edit";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/screen_edit"})
/*      */   public String screen_edit(Model model, HttpSession session) {
/* 1607 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1609 */     Screen screen = (Screen)this.screenService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", user.getMerchant()));
/*      */     
/* 1611 */     model.addAttribute("screen", screen);
/*      */     
/* 1613 */     return "pages_screen_edit";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/poster_list"})
/*      */   public String poster_list(Model model, @ModelAttribute PageModel pageModel, HttpSession session) {
/* 1623 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1625 */     QueryWrapper queryWrapper = new QueryWrapper();
/*      */     
/* 1627 */     queryWrapper.eq("merchant", user.getMerchant());
/*      */     
/* 1629 */     queryWrapper.orderByDesc("create_time");
/*      */ 
/*      */     
/* 1632 */     IPage<Poster> iPage = this.posterService.page((IPage)new Page(pageModel.getPageIndex().intValue(), pageModel.getSize().intValue()), (Wrapper)queryWrapper);
/*      */     
/* 1634 */     model.addAttribute("view", "poster_list");
/*      */     
/* 1636 */     model.addAttribute("iPage", iPage);
/*      */     
/* 1638 */     model.addAttribute("list", iPage.getRecords());
/*      */     
/* 1640 */     return "pages_poster_list";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/poster_design"})
/*      */   public String poster_design(Model model) {
/* 1648 */     AppletConfig appletConfig = (AppletConfig)this.appletConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1650 */     model.addAttribute("appletConfig", appletConfig);
/*      */     
/* 1652 */     return "lyear_poster_design";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/census"})
/*      */   public String census(Model model, @RequestParam(required = false, defaultValue = "1") Integer sale, HttpSession session) {
/* 1661 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1663 */     List<RecordNum> array = new ArrayList<>();
/*      */     
/* 1665 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1667 */     map.put("merchant", user.getMerchant());
/*      */     
/* 1669 */     map.put("sale", sale);
/*      */     
/* 1671 */     array = this.countService.getCount(map);
/*      */     
/* 1673 */     model.addAttribute("array", array);
/*      */     
/* 1675 */     model.addAttribute("sale", sale);
/*      */     
/* 1677 */     return "pages_census";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/pages_config"})
/*      */   public String pages_config(Model model, HttpSession session) {
/* 1691 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1693 */     SystemConfig system = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1696 */     ArticleConfig article = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1699 */     MessageConfig message = (MessageConfig)this.messageConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1702 */     PresetConfig preset = (PresetConfig)this.presetConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1705 */     model.addAttribute("preset", preset);
/*      */     
/* 1707 */     model.addAttribute("article", article);
/*      */     
/* 1709 */     model.addAttribute("message", message);
/*      */     
/* 1711 */     model.addAttribute("system", system);
/* 1712 */     model.addAttribute("configure", configure);
/*      */     
/* 1714 */     return "lyear_config_pages";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/application_config"})
/*      */   public String application_config(Model model) {
/* 1726 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1728 */     OfficialConfig official = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1730 */     model.addAttribute("applet", applet);
/*      */     
/* 1732 */     model.addAttribute("official", official);
/*      */ 
/*      */     
/* 1735 */     return "lyear_config_application";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/payment_config"})
/*      */   public String payment_config(Model model, HttpSession session) {
/* 1745 */     PaymentConfig paymentConfig = (PaymentConfig)this.paymentConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1747 */     WechatAppPayConfig wechatAppPayConfig = (WechatAppPayConfig)this.wechatAppPayConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1750 */     PayAlipayConfig payAlipayConfig = (PayAlipayConfig)this.payAlipayConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1752 */     model.addAttribute("paymentConfig", paymentConfig);
/*      */     
/* 1754 */     model.addAttribute("wechatAppPayConfig", wechatAppPayConfig);
/*      */     
/* 1756 */     model.addAttribute("payAlipayConfig", payAlipayConfig);
/*      */     
/* 1758 */     return "lyear_config_payment";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/edit_pwd"})
/*      */   public String edit_pwd(Model model) {
/* 1766 */     return "pages_edit_pwd";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/record_import"})
/*      */   public String record_import(Model model, HttpSession session) {
/* 1778 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1780 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1782 */     map.put("merchant", user.getMerchant());
/*      */     
/* 1784 */     map.put("sale", Integer.valueOf(1));
/*      */     
/* 1786 */     List<RecordNum> list = this.countService.getCount(map);
/*      */     
/* 1788 */     model.addAttribute("list", list);
/*      */     
/* 1790 */     return "pages_record_import";
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/stock_export"})
/*      */   public String stock_export(Model model, HttpSession session) {
/* 1797 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1799 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1801 */     map.put("merchant", user.getMerchant());
/*      */     
/* 1803 */     List<StockNum> list = this.countService.stockCount(map);
/*      */     
/* 1805 */     model.addAttribute("list", list);
/*      */     
/* 1807 */     return "pages_stock_export";
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping(value = {"/export_excel"}, method = {RequestMethod.GET})
/*      */   public void export_excel(HttpServletResponse response, HttpServletRequest request, HttpSession session) throws Exception {
/* 1821 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1823 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1825 */     List<Stock> list = this.stockService.list();
/*      */ 
/*      */     
/* 1828 */     Set<String> excludeColumnFiledNames = new HashSet<>();
/* 1829 */     excludeColumnFiledNames.add("merchant");
/* 1830 */     excludeColumnFiledNames.add("oid");
/* 1831 */     excludeColumnFiledNames.add("uid");
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */     
/* 1838 */     String excelName = "导出测试";
/*      */     
/* 1840 */     response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
/* 1841 */     response.setCharacterEncoding("utf-8");
/*      */     
/* 1843 */     String fileName = URLEncoder.encode(excelName, "UTF-8").replaceAll("\\+", "%20");
/* 1844 */     response.setHeader("Content-disposition", "attachment;filename*=utf-8''" + fileName + ".xlsx");
/*      */     
/* 1846 */     ((ExcelWriterSheetBuilder)((ExcelWriterSheetBuilder)((ExcelWriterBuilder)EasyExcel.write((OutputStream)response.getOutputStream(), Stock.class).excludeColumnFiledNames(excludeColumnFiledNames)).sheet("数据统计")
/* 1847 */       .registerWriteHandler((WriteHandler)new LongestMatchColumnWidthStyleStrategy()))
/* 1848 */       .useDefaultStyle(Boolean.valueOf(true)))
/* 1849 */       .doWrite(list);
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @ResponseBody
/*      */   @RequestMapping({"/test_export"})
/*      */   public String test_export(Model model, HttpSession session) {
/* 1857 */     User user = (User)session.getAttribute("user");
/*      */     
/* 1859 */     List<User> list = this.userService.list((Wrapper)(new QueryWrapper()).eq("pattern", "deposit"));
/*      */     
/* 1861 */     list.add(user);
/*      */     
/* 1863 */     list.forEach(System.out::println);
/*      */     
/* 1865 */     List<RecordNum> stockNums = this.countService.superRecordCount(list);
/*      */     
/* 1867 */     stockNums.forEach(System.out::println);
/*      */     
/* 1869 */     return "pages_stock_export";
/*      */   }
/*      */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\MainController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */