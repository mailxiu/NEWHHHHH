/*      */ package com.bss.controller;
/*      */ import cn.hutool.captcha.generator.RandomGenerator;
/*      */ import cn.hutool.core.util.RandomUtil;
import com.alibaba.fastjson.JSON;
/*      */ import com.alibaba.fastjson.JSONArray;
/*      */ import com.alibaba.fastjson.JSONObject;
/*      */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*      */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*      */ import com.bss.enmus.AlbumEnum;
import com.bss.enmus.PaymentEnum;
/*      */ import com.bss.entity.*;
import java.util.stream.Collectors;
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
/*      */ import com.bss.service.impl.*;
import com.bss.utils.R;
/*      */ import java.lang.Exception;
import java.math.BigDecimal;
/*      */ import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
/*      */ import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.*;
/*      */
/*      */
/*      */ import javax.annotation.Resource;
/*      */ import javax.servlet.http.HttpSession;
/*      */ import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.bind.annotation.*;
/*      */
/*      */
/*      */
import org.springframework.web.client.RestTemplate;
/*      */ 
/*      */ @RequestMapping({"api"})
/*      */ @RestController
/*      */ public class ApiController {
/*   41 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.ApiController.class);
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private OrderServiceImpl orderService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private RecordServiceImpl recordService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private GradeServiceImpl gradeService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private ProjectServiceImpl projectService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private PosterServiceImpl posterService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private ScreenServiceImpl screenService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private CarouselServiceImpl carouselService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private MarkdownServiceImpl markdownService;
/*      */ 
/*      */   
/*      */   @Resource
/*      */   private CategoryServiceImpl categoryService;
/*      */   
/*      */   @Resource
/*      */   private ConfigureServiceImpl configureService;
/*      */   
/*      */   @Resource
/*      */   private SettlementServiceImpl settlementService;
/*      */   
/*      */   @Resource
/*      */   private AdvertiseServiceImpl advertiseService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintServiceImpl complaintService;
/*      */   
/*      */   @Resource
/*      */   private ExtractConfigServiceImpl extractConfigService;
/*      */   
/*      */   @Resource
/*      */   private SystemConfigServiceImpl systemConfigService;
/*      */   
/*      */   @Resource
/*      */   private ArticleConfigServiceImpl articleConfigService;
/*      */   
/*      */   @Resource
/*      */   private OfficialConfigServiceImpl officialConfigService;
/*      */   
/*      */   @Resource
/*      */   private DetailsServiceImpl detailsService;
/*      */   
/*      */   @Resource
/*      */   private WxtPayServiceImpl wxtPayService;
/*      */   
/*      */   @Resource
/*      */   private AlipayServiceImpl alipayService;
/*      */   
/*      */   @Resource
/*      */   private MemberServiceImpl memberService;
/*      */   
/*      */   @Resource
/*      */   private MessageServiceImpl messageService;
/*      */   
/*      */   @Resource
/*      */   private DepositServiceImpl depositService;
/*      */   
/*      */   @Resource
/*      */   private WithdrawalServiceImpl withdrawalService;
/*      */   
/*      */   @Resource
/*      */   private YinShengPayServiceImpl yinShengPayService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintItemServiceImpl complaintItemService;
/*      */   
/*      */   @Resource
/*      */   private ComplaintReferServiceImpl complaintReferService;
/*      */   
/*      */   @Resource
/*      */   private SandPayServiceImpl sandPayService;
/*      */   
/*      */   @Resource
/*      */   private HuiFuPayServiceImp huiFuPayService;
/*      */   
/*      */   @Resource
/*      */   private ShortMessagesServiceImpl shortMessagesService;
/*      */   
/*      */   @Resource
/*      */   private PresetConfigServiceImpl presetConfigService;
/*      */ 
/*      */   
/*      */   @RequestMapping({"/binding_wechat"})
/*      */   public R binding_wechat(@RequestParam("code") String code, String uid) {
/*  148 */     System.out.println("收到绑定请求");
/*      */     
/*  150 */     String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=wx3afffd1bbcb26fdd&secret=db1f68c2391a1a94d86406ce57307692&code=" + code + "&grant_type=authorization_code";
/*      */     
/*  152 */     RestTemplate restTemplate = new RestTemplate();
/*  153 */     String result = (String)restTemplate.getForObject(url, String.class, new Object[0]);
/*      */     
/*  155 */     JSONObject object = JSON.parseObject(result);
/*      */     
/*  157 */     String access_token = object.getString("access_token");
/*      */     
/*  159 */     String unionid = object.getString("unionid");
/*      */     
/*  161 */     String openid = object.getString("openid");
/*      */ 
/*      */     
/*  164 */     Member member_openid = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("unionid", unionid));
/*      */     
/*  166 */     System.out.println("查询用户：" + member_openid);
/*      */     
/*  168 */     if (member_openid != null) {
/*  169 */       return R.fail("绑定失败,已存在绑定关系");
/*      */     }
/*      */     
/*  172 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/*  174 */     String userurl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + access_token + "&openid=" + unionid;
/*      */     
/*  176 */     restTemplate.getMessageConverters().set(1, new StringHttpMessageConverter(StandardCharsets.UTF_8));
/*      */     
/*  178 */     String resultUser = (String)restTemplate.getForObject(userurl, String.class, new Object[0]);
/*      */     
/*  180 */     JSONObject userData = JSON.parseObject(resultUser);
/*      */     
/*  182 */     String name = userData.getString("nickname");
/*  183 */     String image = userData.getString("headimgurl");
/*      */     
/*  185 */     member.setUnionid(unionid);
/*  186 */     member.setOpenid(openid);
/*  187 */     member.setName(name);
/*  188 */     member.setPortrait(image);
/*      */     
/*  190 */     boolean update = this.memberService.saveOrUpdate(member);
/*      */     
/*  192 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */     
/*  194 */     JSONObject data = (JSONObject)JSON.toJSON(member);
/*      */     
/*  196 */     data.put("grade_name", grade.getName());
/*      */     
/*  198 */     return R.success(data);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/appleLogin"})
/*      */   public R appleLogin(@RequestBody JSONObject data) {
/*  208 */     System.out.println("苹果登录授权返回:" + data.toString());
/*      */ 
/*      */     
/*  211 */     JSONObject rq = data.getJSONObject("data");
/*      */     
/*  213 */     if (rq.getString("errMsg").equals("getUserInfo:ok")) {
/*      */       
/*  215 */       JSONObject userInfo = rq.getJSONObject("userInfo");
/*      */       
/*  217 */       String openId = userInfo.getString("openId");
/*      */       
/*  219 */       JSONObject fullName = userInfo.getJSONObject("fullName");
/*  220 */       StringBuilder sb = new StringBuilder();
/*      */       
/*  222 */       sb.append(fullName.getString("familyName"));
/*      */       
/*  224 */       sb.append(fullName.getString("giveName"));
/*      */       
/*  226 */       System.out.println("用户名：" + sb.toString());
/*      */       
/*  228 */       System.out.println(openId);
/*      */       
/*  230 */       Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", openId));
/*      */       
/*  232 */       if (member == null) {
/*      */         
/*  234 */         member = new Member();
/*      */         
/*  236 */         PresetConfig presetConfig = (PresetConfig)this.presetConfigService.getOne((Wrapper)new QueryWrapper());
/*      */         
/*  238 */         String randomStringUpper = RandomUtil.randomStringUpper(10);
/*      */         
/*  240 */         member.setId(Integer.valueOf(0));
/*  241 */         member.setMid("0");
/*  242 */         member.setMerchant("100000");
/*  243 */         member.setOpenid(openId);
/*  244 */         member.setName(sb.toString());
/*  245 */         member.setPortrait(presetConfig.getDefaultPortrait());
/*  246 */         member.setPoints(Double.valueOf(0.0D));
/*  247 */         member.setPartner(Integer.valueOf(1));
/*  248 */         member.setInvitationCode(randomStringUpper);
/*  249 */         member.setState("已激活");
/*      */         
/*  251 */         this.memberService.save(member);
/*      */         
/*  253 */         String uid = String.valueOf(Integer.valueOf(member.getId().toString()).intValue() + 100000);
/*      */         
/*  255 */         member.setUid(uid);
/*      */         
/*  257 */         boolean update = this.memberService.saveOrUpdate(member);
/*      */         
/*  259 */         Grade grade1 = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */         
/*  261 */         JSONObject jSONObject = (JSONObject)JSON.toJSON(member);
/*      */         
/*  263 */         jSONObject.put("grade_name", grade1.getName());
/*      */ 
/*      */ 
/*      */         
/*  267 */         jSONObject.put("binding", Boolean.valueOf(true));
/*      */         
/*  269 */         return R.success(jSONObject);
/*      */       } 
/*      */ 
/*      */       
/*  273 */       if (!member.getState().equals("已激活")) {
/*  274 */         return R.fail("账号状态异常禁止登录");
/*      */       }
/*      */       
/*  277 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */       
/*  279 */       JSONObject datat = (JSONObject)JSON.toJSON(member);
/*      */       
/*  281 */       datat.put("grade_name", grade.getName());
/*      */       
/*  283 */       datat.put("binding", Boolean.valueOf(true));
/*      */       
/*  285 */       return R.success(datat);
/*      */     } 
/*      */ 
/*      */ 
/*      */     
/*  290 */     return R.fail("登录失败");
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
/*      */   @RequestMapping({"/wx"})
/*      */   public R auth(@RequestParam("code") String code) {
/*  305 */     System.out.println("收到APP微信授权登录回调");
/*      */     
/*  307 */     String url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=wx3afffd1bbcb26fdd&secret=db1f68c2391a1a94d86406ce57307692&code=" + code + "&grant_type=authorization_code";
/*  308 */     RestTemplate restTemplate = new RestTemplate();
/*  309 */     String result = (String)restTemplate.getForObject(url, String.class, new Object[0]);
/*      */     
/*  311 */     JSONObject object = JSON.parseObject(result);
/*      */     
/*  313 */     String access_token = object.getString("access_token");
/*      */     
/*  315 */     String unionid = object.getString("unionid");
/*      */     
/*  317 */     String openid = object.getString("openid");
/*      */ 
/*      */     
/*  320 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("unionid", unionid));
/*      */     
/*  322 */     if (member == null) {
/*      */       
/*  324 */       String userurl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + access_token + "&openid=" + unionid;
/*      */       
/*  326 */       restTemplate.getMessageConverters().set(1, new StringHttpMessageConverter(StandardCharsets.UTF_8));
/*      */       
/*  328 */       String resultUser = (String)restTemplate.getForObject(userurl, String.class, new Object[0]);
/*      */       
/*  330 */       JSONObject userData = JSON.parseObject(resultUser);
/*      */       
/*  332 */       String name = userData.getString("nickname");
/*  333 */       String image = userData.getString("headimgurl");
/*      */       
/*  335 */       member = new Member();
/*      */       
/*  337 */       PresetConfig presetConfig = (PresetConfig)this.presetConfigService.getOne((Wrapper)new QueryWrapper());
/*      */       
/*  339 */       String str1 = RandomUtil.randomStringUpper(10);
/*      */       
/*  341 */       member.setId(Integer.valueOf(0));
/*  342 */       member.setMid("0");
/*  343 */       member.setMerchant("100000");
/*  344 */       member.setUnionid(unionid);
/*  345 */       member.setOpenid(openid);
/*  346 */       member.setName(name);
/*  347 */       member.setPortrait(image);
/*  348 */       member.setPoints(Double.valueOf(0.0D));
/*  349 */       member.setPartner(Integer.valueOf(1));
/*  350 */       member.setInvitationCode(str1);
/*  351 */       member.setState("已激活");
/*      */       
/*  353 */       this.memberService.save(member);
/*      */       
/*  355 */       String uid = String.valueOf(Integer.valueOf(member.getId().toString()).intValue() + 100000);
/*      */       
/*  357 */       member.setUid(uid);
/*      */       
/*  359 */       boolean update = this.memberService.saveOrUpdate(member);
/*      */       
/*  361 */       Grade grade1 = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */       
/*  363 */       JSONObject datat = (JSONObject)JSON.toJSON(member);
/*      */       
/*  365 */       datat.put("grade_name", grade1.getName());
/*      */ 
/*      */ 
/*      */       
/*  369 */       datat.put("binding", Boolean.valueOf(true));
/*      */       
/*  371 */       return R.success(datat);
/*      */     } 
/*      */ 
/*      */     
/*  375 */     if (member.getOpenid() == null || member.getOpenid().equals("")) {
/*  376 */       member.setOpenid(openid);
/*  377 */       this.memberService.saveOrUpdate(member);
/*      */     } 
/*      */     
/*  380 */     if (!member.getState().equals("已激活")) {
/*  381 */       return R.fail("账号状态异常禁止登录");
/*      */     }
/*      */     
/*  384 */     String randomStringUpper = RandomUtil.randomStringUpper(10);
/*      */     
/*  386 */     if (member.getInvitationCode() == null) {
/*  387 */       member.setInvitationCode(randomStringUpper);
/*  388 */       this.memberService.saveOrUpdate(member);
/*      */     } 
/*      */     
/*  391 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */     
/*  393 */     JSONObject data = (JSONObject)JSON.toJSON(member);
/*      */     
/*  395 */     data.put("grade_name", grade.getName());
/*      */     
/*  397 */     if (member.getPhone() == null || member.getPhone().equals("")) {
/*  398 */       data.put("binding", Boolean.valueOf(false));
/*      */     } else {
/*  400 */       data.put("binding", Boolean.valueOf(true));
/*      */     } 
/*      */     
/*  403 */     return R.success(data);
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
/*      */   @PostMapping({"/send_code"})
/*      */   public R sendCode(String phone, HttpSession session) {
/*  416 */     if (phone.equals("13888888888")) {
/*  417 */       session.setAttribute("code", "666666");
/*  418 */       return R.success(Boolean.valueOf(true));
/*      */     } 
/*      */     
/*  421 */     Long timestamp = (Long)session.getAttribute("timestamp");
/*      */     
/*  423 */     Integer total = (Integer)session.getAttribute("total");
/*      */     
/*  425 */     if (timestamp != null) {
/*      */       
/*  427 */       long timeMillis = System.currentTimeMillis();
/*      */       
/*  429 */       if (Math.abs(timeMillis - timestamp.longValue()) < 60000L) {
/*  430 */         return R.fail("验证码获取频繁请等待");
/*      */       }
/*      */     } else {
/*      */       
/*  434 */       session.setAttribute("timestamp", Long.valueOf(System.currentTimeMillis()));
/*      */     } 
/*      */     
/*  437 */     if (total != null) {
/*  438 */       total = Integer.valueOf(total.intValue() + 1);
/*  439 */       session.setAttribute("total", total);
/*      */     } else {
/*      */       
/*  442 */       total = Integer.valueOf(1);
/*  443 */       session.setAttribute("total", total);
/*      */     } 
/*      */     
/*  446 */     if (total.intValue() >= 10) {
/*  447 */       return R.fail("今日接收验证码次数已耗尽");
/*      */     }
/*      */     
/*  450 */     System.out.println("手机号：" + phone);
/*      */ 
/*      */ 
/*      */     
/*  454 */     R r = this.shortMessagesService.verification_code(phone);
/*      */     
/*  456 */     if (!r.getCode().equals(Integer.valueOf(20000))) {
/*  457 */       return r;
/*      */     }
/*  459 */     String code = r.getMsg();
/*      */     
/*  461 */     session.setAttribute("code", code);
/*      */     
/*  463 */     log.info("验证码：{}", code);
/*      */     
/*  465 */     return R.success(Boolean.valueOf(true));
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
/*      */   @RequestMapping({"/login_phone"})
/*      */   public R login_phone(String phone, String verification_code, HttpSession session) {
/*  478 */     String code = (String)session.getAttribute("code");
/*      */     
/*  480 */     if (verification_code == null || code == null) {
/*  481 */       return R.fail("验证码异常");
/*      */     }
/*      */     
/*  484 */     if (!code.equals(verification_code)) {
/*  485 */       return R.fail("验证码错误");
/*      */     }
/*      */     
/*  488 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", phone));
/*      */     
/*  490 */     if (member == null) {
/*  491 */       return R.fail("首次使用APP的用户请使用微信登录");
/*      */     }
/*      */     
/*  494 */     if (!member.getState().equals("已激活")) {
/*  495 */       return R.fail("账号状态异常禁止登录");
/*      */     }
/*      */     
/*  498 */     String randomStringUpper = RandomUtil.randomStringUpper(10);
/*      */     
/*  500 */     if (member.getInvitationCode() == null) {
/*  501 */       member.setInvitationCode(randomStringUpper);
/*  502 */       this.memberService.saveOrUpdate(member);
/*      */     } 
/*      */     
/*  505 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", member.getPartner()));
/*      */     
/*  507 */     JSONObject data = (JSONObject)JSON.toJSON(member);
/*      */     
/*  509 */     data.put("grade_name", grade.getName());
/*      */     
/*  511 */     if (member.getOpenid() == null || member.getOpenid().equals("")) {
/*  512 */       data.put("binding", Boolean.valueOf(false));
/*      */     } else {
/*  514 */       data.put("binding", Boolean.valueOf(true));
/*      */     } 
/*      */     
/*  517 */     return R.success(data);
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
/*      */   @PostMapping({"/updateMember"})
/*      */   public R updateMember(@RequestBody String jsonStr, HttpSession session) {
/*  532 */     JSONObject o = JSONObject.parseObject(jsonStr);
/*      */     
/*  534 */     String verification_code = o.getString("verification_code");
/*      */     
/*  536 */     String code = (String)session.getAttribute("code");
/*      */     
/*  538 */     if (verification_code == null || code == null) {
/*  539 */       return R.fail("验证码异常");
/*      */     }
/*      */     
/*  542 */     if (!code.equals(verification_code)) {
/*  543 */       return R.fail("验证码错误");
/*      */     }
/*      */ 
/*      */     
/*  547 */     Member memberPhone = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("phone", o.getString("phone")));
/*      */     
/*  549 */     if (memberPhone != null) {
/*  550 */       return R.fail("手机号已被绑定");
/*      */     }
/*      */     
/*  553 */     String uid = o.getString("uid");
/*      */     
/*  555 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/*  557 */     member.setName(o.getString("name"));
/*  558 */     member.setPhone(o.getString("phone"));
/*      */     
/*  560 */     boolean b = this.memberService.saveOrUpdate(member);
/*      */     
/*  562 */     return R.success(member);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/agreement_list"})
/*      */   public R agreement_list() {
/*  573 */     List<Markdown> list = this.markdownService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("album", AlbumEnum.AGREEMENT)).eq("state", Integer.valueOf(1)));
/*      */     
/*  575 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/cancel_article"})
/*      */   public R cancel_article() {
/*  585 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/*  587 */     if (articleConfig == null || articleConfig.getPrivacyArticle() == null) {
/*  588 */       return R.fail("未配置");
/*      */     }
/*  590 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getCancelArticle()));
/*      */     
/*  592 */     if (markdown == null) {
/*  593 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/*  596 */     return R.success(markdown);
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
/*      */   @PostMapping({"/bank_collection"})
/*      */   public R bank_collection(String openid, String bankRealName, String bankCardNumber, String bankAccountName) {
/*  612 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", openid));
/*      */ 
/*      */     
/*  615 */     if (member == null) {
/*  616 */       return R.fail("用户不存在");
/*      */     }
/*      */     
/*  619 */     member.setBankRealName(bankRealName);
/*      */     
/*  621 */     member.setBankCardNumber(bankCardNumber);
/*      */     
/*  623 */     member.setBankAccountName(bankAccountName);
/*      */     
/*  625 */     boolean saveOrUpdate = this.memberService.saveOrUpdate(member);
/*      */     
/*  627 */     if (saveOrUpdate) {
/*  628 */       return R.success();
/*      */     }
/*  630 */     return R.fail("保存失败");
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
/*      */   @PostMapping({"/alipay_collection"})
/*      */   public R alipay_collection(String openid, String alipayName, String alipayAccount) {
/*  644 */     if (openid == null || openid.equals("")) {
/*  645 */       return R.fail("请先绑定微信");
/*      */     }
/*      */ 
/*      */     
/*  649 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", openid));
/*      */ 
/*      */     
/*  652 */     if (member == null) {
/*  653 */       return R.fail("用户不存在");
/*      */     }
/*      */ 
/*      */     
/*  657 */     member.setAlipayName(alipayName);
/*      */     
/*  659 */     member.setAlipayAccount(alipayAccount);
/*      */     
/*  661 */     boolean saveOrUpdate = this.memberService.saveOrUpdate(member);
/*      */     
/*  663 */     if (saveOrUpdate) {
/*  664 */       return R.success();
/*      */     }
/*  666 */     return R.fail("保存失败");
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/complaint_refer"})
/*      */   public R complaint_refer() {
/*  677 */     List<ComplaintRefer> list = this.complaintReferService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("state", Integer.valueOf(1))).orderByDesc("sort"));
/*      */     
/*  679 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/complaint_list"})
/*      */   public R complaint_list(String uid) {
/*  691 */     List<Complaint> list = this.complaintService.list((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("complaint_uid", uid)).eq("state", Integer.valueOf(0))).orderByDesc("create_time"));
/*      */     
/*  693 */     if (list.size() == 0) {
/*  694 */       return R.fail("未提交");
/*      */     }
/*      */     
/*  697 */     Complaint complaint = list.get(0);
/*      */ 
/*      */     
/*  700 */     List<ComplaintItem> items = this.complaintItemService.list((Wrapper)(new QueryWrapper()).eq("complaint_number", complaint.getComplaintNumber()));
/*      */ 
/*      */     
/*  703 */     JSONArray itemsJson = JSONArray.parseArray(JSON.toJSONString(items));
/*      */     
/*  705 */     for (int i = 0; i < itemsJson.size(); i++) {
/*      */       
/*  707 */       JSONObject jsonObject = itemsJson.getJSONObject(i);
/*      */       
/*  709 */       String images = jsonObject.getString("images");
/*      */       
/*  711 */       if (images.length() < 6) {
/*  712 */         jsonObject.put("images", new String[0]);
/*      */       } else {
/*  714 */         String[] split = images.split(",");
/*      */         
/*  716 */         jsonObject.put("images", split);
/*      */       } 
/*      */     } 
/*      */     
/*  720 */     JSONObject data = (JSONObject)JSON.toJSON(complaint);
/*      */     
/*  722 */     data.put("items", itemsJson);
/*      */     
/*  724 */     return R.success(data);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/submit_complaint"})
/*      */   public R submit_complaint(@RequestBody ComplaintVo complaintVo) {
/*  736 */     List<Complaint> list = this.complaintService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("complaint_uid", complaintVo.getComplaintUid())).eq("state", Integer.valueOf(0)));
/*      */     
/*  738 */     if (list.size() != 0) {
/*  739 */       return R.fail("您有投诉未处理，请处理后再提交");
/*      */     }
/*      */ 
/*      */     
/*  743 */     Calendar calendar = Calendar.getInstance();
/*      */     
/*  745 */     DateFormat dateSalt = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/*  747 */     RandomGenerator randomGenerator = new RandomGenerator("123456789", 4);
/*      */     
/*  749 */     StringBuilder complaintNumber = new StringBuilder();
/*      */     
/*  751 */     complaintNumber.append("TS");
/*      */     
/*  753 */     complaintNumber.append(dateSalt.format(calendar.getTime()));
/*      */     
/*  755 */     complaintNumber.append(randomGenerator.generate());
/*      */ 
/*      */     
/*  758 */     String[] imageArr = complaintVo.getImages();
/*      */ 
/*      */ 
/*      */     
/*  762 */     StringBuilder images = new StringBuilder();
/*      */     
/*  764 */     for (int i = 0; i < imageArr.length; i++) {
/*  765 */       images.append(imageArr[i]);
/*      */       
/*  767 */       if (i < imageArr.length - 1) {
/*  768 */         images.append(",");
/*      */       }
/*      */     } 
/*      */ 
/*      */     
/*  773 */     Complaint complaint = new Complaint();
/*  774 */     complaint.setId(Integer.valueOf(0));
/*  775 */     complaint.setComplaintNumber(complaintNumber.toString());
/*  776 */     complaint.setComplaintUid(complaintVo.getComplaintUid());
/*  777 */     complaint.setComplaintRefer(complaintVo.getComplaintRefer());
/*  778 */     complaint.setContent(complaintVo.getContent());
/*  779 */     complaint.setPhone(complaintVo.getPhone());
/*  780 */     complaint.setImages(images.toString());
/*  781 */     complaint.setState(Integer.valueOf(0));
/*      */     
/*  783 */     this.complaintService.save(complaint);
/*      */ 
/*      */     
/*  786 */     ComplaintItem complaintItem = new ComplaintItem();
/*      */     
/*  788 */     complaintItem.setId(Integer.valueOf(0));
/*      */     
/*  790 */     complaintItem.setSessionType("member");
/*      */     
/*  792 */     complaintItem.setComplaintNumber(complaintNumber.toString());
/*      */     
/*  794 */     complaintItem.setContent(complaintVo.getContent());
/*      */     
/*  796 */     complaintItem.setImages(images.toString());
/*      */     
/*  798 */     this.complaintItemService.save(complaintItem);
/*      */     
/*  800 */     return R.success(Boolean.valueOf(true));
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
/*      */   @RequestMapping({"/supply_complaint"})
/*      */   public R supply_complaint(@RequestBody ComplaintVo complaintVo) {
/*  813 */     Complaint complaint = (Complaint)this.complaintService.getOne((Wrapper)(new QueryWrapper()).eq("complaint_number", complaintVo.getComplaintNumber()));
/*      */     
/*  815 */     if (complaint == null) {
/*  816 */       return R.fail("投诉不存在");
/*      */     }
/*      */ 
/*      */     
/*  820 */     String[] imageArr = complaintVo.getImages();
/*      */ 
/*      */ 
/*      */     
/*  824 */     StringBuilder images = new StringBuilder();
/*      */     
/*  826 */     for (int i = 0; i < imageArr.length; i++) {
/*  827 */       images.append(imageArr[i]);
/*      */       
/*  829 */       if (i < imageArr.length - 1) {
/*  830 */         images.append(",");
/*      */       }
/*      */     } 
/*      */ 
/*      */     
/*  835 */     ComplaintItem complaintItem = new ComplaintItem();
/*  836 */     complaintItem.setId(Integer.valueOf(0));
/*      */     
/*  838 */     complaintItem.setSessionType("member");
/*      */     
/*  840 */     complaintItem.setComplaintNumber(complaint.getComplaintNumber());
/*      */     
/*  842 */     complaintItem.setContent(complaintVo.getContent());
/*      */     
/*  844 */     complaintItem.setImages(images.toString());
/*      */     
/*  846 */     this.complaintItemService.save(complaintItem);
/*      */     
/*  848 */     return R.success(Boolean.valueOf(true));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/get_message"})
/*      */   public R get_message(String uid) {
/*  860 */     List<Message> list = this.messageService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("state", Integer.valueOf(0)));
/*      */     
/*  862 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/look_message"})
/*      */   public R look_message(String uid, Integer id) {
/*  874 */     Message message = (Message)this.messageService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("id", id));
/*      */     
/*  876 */     message.setState(Integer.valueOf(1));
/*      */     
/*  878 */     boolean update = this.messageService.updateById(message);
/*      */     
/*  880 */     return R.success(Boolean.valueOf(update));
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
/*      */   @RequestMapping({"/supplement"})
/*      */   public R supplement() {
/*  893 */     List<Member> list = this.memberService.list((Wrapper)(new QueryWrapper()).ne("partner", Integer.valueOf(1)));
/*      */ 
/*      */ 
/*      */     
/*  897 */     for (int i = 0; i < list.size(); i++) {
/*      */ 
/*      */ 
/*      */       
/*  901 */       Deposit deposit = (Deposit)this.depositService.getOne((Wrapper)(new QueryWrapper()).eq("uid", ((Member)list.get(i)).getUid()));
/*      */       
/*  903 */       if (deposit == null) {
/*      */         
/*  905 */         deposit = new Deposit();
/*      */         
/*  907 */         deposit.setState(Boolean.valueOf(false));
/*      */         
/*  909 */         deposit.setUid(((Member)list.get(i)).getUid());
/*      */         
/*  911 */         deposit.setMoney(new BigDecimal(((Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", ((Member)list.get(i)).getMerchant())).eq("sort", ((Member)list.get(i)).getPartner()))).getPrice().toString()));
/*      */         
/*  913 */         this.depositService.saveOrUpdate(deposit);
/*      */       } 
/*      */     } 
/*      */ 
/*      */ 
/*      */     
/*  919 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/order_payment_type"})
/*      */   public R order_payment_type() {
/*  929 */     Order order = (Order)this.orderService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).orderByDesc("create_time")).last("limit 1"));
/*      */ 
/*      */     
/*  932 */     if (order.getPaymentType() == PaymentEnum.YSWxPay) {
/*  933 */       return R.success("yinsheng");
/*      */     }
/*  935 */     return R.success("official");
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/carouse_list"})
/*      */   public R carouse_list(String merchant) {
/*  947 */     List<Carousel> list = this.carouselService.list((Wrapper)(new QueryWrapper()).eq("merchant", merchant));
/*      */     
/*  949 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/project_details"})
/*      */   public R project_details(String merchant, Integer pid) {
/*  961 */     Details details = (Details)this.detailsService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("pid", pid));
/*      */     
/*  963 */     if (details == null) {
/*  964 */       details = new Details();
/*      */       
/*  966 */       details.setMd("暂未配置");
/*      */     } 
/*      */     
/*  969 */     return R.success(details);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/screen"})
/*      */   public R screen() {
/*  978 */     Screen screen = (Screen)this.screenService.getOne((Wrapper)new QueryWrapper());
/*  979 */     return R.success(screen);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/advertise"})
/*      */   public R advertise(String merchant) {
/*  989 */     Advertise advertise = (Advertise)this.advertiseService.getOne((Wrapper)(new QueryWrapper()).eq("merchant", merchant));
/*  990 */     return R.success(advertise);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/getMarkdown"})
/*      */   public R getMarkdown(Integer id) {
/* 1001 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", id));
/*      */     
/* 1003 */     if (markdown == null) {
/* 1004 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1007 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/user_article"})
/*      */   public R user_article() {
/* 1016 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1018 */     if (articleConfig == null || articleConfig.getUserArticle() == null) {
/* 1019 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1022 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getUserArticle()));
/*      */     
/* 1024 */     if (markdown == null) {
/* 1025 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1028 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/privacy_article"})
/*      */   public R privacy_article() {
/* 1037 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1039 */     if (articleConfig == null || articleConfig.getPrivacyArticle() == null) {
/* 1040 */       return R.fail("未配置");
/*      */     }
/* 1042 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getPrivacyArticle()));
/*      */     
/* 1044 */     if (markdown == null) {
/* 1045 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1048 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/member_article"})
/*      */   public R member_article() {
/* 1059 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1061 */     if (articleConfig == null || articleConfig.getCourseArticle() == null) {
/* 1062 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1065 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getMemberArticle()));
/*      */     
/* 1067 */     if (markdown == null) {
/* 1068 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1071 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/course_article"})
/*      */   public R course_article() {
/* 1082 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1084 */     if (articleConfig == null || articleConfig.getCourseArticle() == null) {
/* 1085 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1088 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getCourseArticle()));
/*      */     
/* 1090 */     if (markdown == null) {
/* 1091 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1094 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/bond_article"})
/*      */   public R bond_article() {
/* 1105 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1107 */     if (articleConfig == null || articleConfig.getBondArticle() == null) {
/* 1108 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1111 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getBondArticle()));
/*      */     
/* 1113 */     if (markdown == null) {
/* 1114 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1117 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/guide_article"})
/*      */   public R guide_article() {
/* 1128 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1130 */     if (articleConfig == null || articleConfig.getGuideArticle() == null) {
/* 1131 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1134 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getGuideArticle()));
/*      */     
/* 1136 */     if (markdown == null) {
/* 1137 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1140 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/agreement_article"})
/*      */   public R agreement_article() {
/* 1149 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1151 */     if (articleConfig == null || articleConfig.getUserArticle() == null) {
/* 1152 */       return R.fail("未配置");
/*      */     }
/*      */     
/* 1155 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getUserArticle()));
/*      */     
/* 1157 */     if (markdown == null) {
/* 1158 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1161 */     return R.success(markdown);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/customer_article"})
/*      */   public R customer_article() {
/* 1171 */     ArticleConfig articleConfig = (ArticleConfig)this.articleConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1173 */     if (articleConfig == null || articleConfig.getCourseArticle() == null) {
/* 1174 */       return R.fail("未配置");
/*      */     }
/* 1176 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)(new QueryWrapper()).eq("id", articleConfig.getCustomerArticle()));
/*      */     
/* 1178 */     if (markdown == null) {
/* 1179 */       return R.fail("文章不存在");
/*      */     }
/*      */     
/* 1182 */     return R.success(markdown);
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
/*      */   @PostMapping({"order_add"})
/*      */   public R order_add(@RequestBody OrderVo orderVo) {
/* 1197 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", orderVo.getSort()));
/*      */ 
/*      */     
/* 1200 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("unionid", orderVo.getUnionid()));
/*      */     
/* 1202 */     if (member == null) {
/* 1203 */       member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", orderVo.getOpenid()));
/*      */     }
/*      */     
/* 1206 */     if (grade == null) {
/* 1207 */       return R.fail("等级不存在");
/*      */     }
/*      */     
/* 1210 */     if (member == null) {
/* 1211 */       return R.fail("用户不存在");
/*      */     }
/*      */     
/* 1214 */     Calendar calendar = Calendar.getInstance();
/*      */     
/* 1216 */     DateFormat orderId = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/* 1218 */     RandomGenerator randomGenerator = new RandomGenerator("123456789", 4);
/*      */     
/* 1220 */     String oid = orderId.format(calendar.getTime()) + randomGenerator.generate();
/*      */ 
/*      */     
/* 1223 */     int num = RandomUtil.randomInt(-8, 2);
/*      */     
/* 1225 */     BigDecimal salt_num = new BigDecimal(num);
/*      */     
/* 1227 */     BigDecimal salt = salt_num.setScale(1, 4);
/*      */     
/* 1229 */     Order order = new Order();
/* 1230 */     order.setId(Integer.valueOf(0));
/* 1231 */     order.setPartner(grade.getName());
/* 1232 */     order.setSort(orderVo.getSort());
/* 1233 */     order.setUid(member.getUid());
/* 1234 */     order.setOid(oid);
/* 1235 */     order.setMoney((new BigDecimal(grade.getPrice().doubleValue())).add(salt));
/* 1236 */     order.setPaymentType(PaymentEnum.valueOf(orderVo.getPaymentType()));
/* 1237 */     order.setState("待支付");
/*      */     
/* 1239 */     this.orderService.save(order);
/*      */     
/* 1241 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.WeChat))
/*      */     {
/*      */       
/* 1244 */       return this.wxtPayService.goWXAlipayJS(order.getOid(), member.getOpenid());
/*      */     }
/* 1246 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.WeChatJSAPI)) {
/*      */ 
/*      */       
/* 1249 */       R goWXAlipayOfficial = this.wxtPayService.goWXAlipayOfficial(order.getOid(), orderVo.getOpenid());
/*      */       
/* 1251 */       System.out.println(goWXAlipayOfficial);
/*      */       
/* 1253 */       return goWXAlipayOfficial;
/*      */     } 
/* 1255 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.YSWxPay))
/*      */     {
/* 1257 */       return this.yinShengPayService.goYinShengPayBFWechatXcxZY(order.getOid(), member.getOpenid());
/*      */     }
/*      */     
/* 1260 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.HuiFuQuick)) {
/*      */       
/*      */       try {
/* 1263 */         return this.huiFuPayService.huiFuQuickPayment(order.getOid());
/*      */       }
/* 1265 */       catch (Exception e) {
/* 1266 */         System.out.println("汇付创建支付发生异常：" + order.toString());
/* 1267 */         throw new RuntimeException(e);
/*      */       } 
/*      */     }
/* 1270 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.AlipayApp))
/*      */     {
/* 1272 */       return this.alipayService.payment_order(order.getOid());
/*      */     }
/*      */     
/* 1275 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.WeChatApp))
/*      */     {
/* 1277 */       return this.wxtPayService.goWeChatAppPay(order.getOid());
/*      */     }
/* 1279 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.SendPay) || PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.SendYLPay))
/*      */     {
/* 1281 */       return this.sandPayService.testReceiptsOrderCreate(order.getOid());
/*      */     }
/* 1283 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.Alipay))
/*      */     {
/* 1285 */       return R.success(order.getOid());
/*      */     }
/* 1287 */     if (PaymentEnum.valueOf(orderVo.getPaymentType()).equals(PaymentEnum.Advance)) {
/* 1288 */       return R.fail("未开启余额支付,下单失败！");
/*      */     }
/* 1290 */     return R.fail("支付类型异常,下单失败！");
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
/*      */   @PostMapping({"system"})
/*      */   public R system() throws Exception {
/* 1306 */     SystemConfig config = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1308 */     if (config == null) {
/* 1309 */       return R.fail("系统未配置");
/*      */     }
/*      */     
/* 1312 */     return R.success(config);
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @RequestMapping({"/getMemberByUid"})
/*      */   public R getMemberByUid(String uid) {
/* 1319 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/* 1321 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", member.getMerchant())).eq("sort", member.getPartner()));
/*      */     
/* 1323 */     JSONObject data = (JSONObject)JSON.toJSON(member);
/*      */     
/* 1325 */     data.put("grade_name", grade.getName());
/*      */     
/* 1327 */     return R.success(data);
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
/*      */   @RequestMapping({"census"})
/*      */   public R census(String uid, String merchant) throws Exception {
/* 1342 */     JSONObject data = new JSONObject();
/*      */     
/* 1344 */     Map<String, Object> map = new HashMap<>();
/*      */     
/* 1346 */     QueryWrapper<Settlement> allQueryWrapper = new QueryWrapper();
/*      */     
/* 1348 */     allQueryWrapper.select(new String[] { "IFNULL(sum(total),0) as points" });
/*      */     
/* 1350 */     allQueryWrapper.eq("uid", uid);
/*      */     
/* 1352 */     map = this.settlementService.getMap((Wrapper)allQueryWrapper);
/*      */     
/* 1354 */     Double all_sum = (Double)map.get("points");
/* 1355 */     data.put("all_sum", all_sum);
/*      */     
/* 1357 */     QueryWrapper<Settlement> moonQueryWrapper = new QueryWrapper();
/*      */     
/* 1359 */     moonQueryWrapper.select(new String[] { "IFNULL(sum(total),0) as points" });
/*      */     
/* 1361 */     moonQueryWrapper.eq("uid", uid);
/*      */     
/* 1363 */     moonQueryWrapper.apply("create_time BETWEEN CONCAT(YEAR(CURRENT_DATE()), '-', MONTH(CURRENT_DATE()), '-01') AND LAST_DAY(CURRENT_DATE())", new Object[0]);
/*      */     
/* 1365 */     map = this.settlementService.getMap((Wrapper)moonQueryWrapper);
/*      */     
/* 1367 */     Double moon_sum = (Double)map.get("points");
/* 1368 */     data.put("moon_sum", moon_sum);
/*      */     
/* 1370 */     QueryWrapper<Settlement> dayQueryWrapper = new QueryWrapper();
/*      */     
/* 1372 */     dayQueryWrapper.select(new String[] { "IFNULL(sum(total),0) as points" });
/*      */     
/* 1374 */     dayQueryWrapper.eq("uid", uid);
/*      */     
/* 1376 */     dayQueryWrapper.apply("TO_DAYS(NOW())-TO_DAYS(create_time) = 0", new Object[0]);
/*      */     
/* 1378 */     map = this.settlementService.getMap((Wrapper)dayQueryWrapper);
/*      */     
/* 1380 */     Double day_sum = (Double)map.get("points");
/* 1381 */     data.put("day_sum", day_sum);
/*      */     
/* 1383 */     return R.success(data);
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
/*      */   public R project_list(@RequestParam(name = "merchant") String merchant, Integer sort, String total) {
/* 1397 */     List<Category> categoryList = this.categoryService.list((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", Integer.valueOf(1))).orderByDesc("sort"));
/*      */     
/* 1399 */     double gain = 1.0D;
/*      */     
/* 1401 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("sort", sort));
/*      */     
/* 1403 */     gain = grade.getGain().doubleValue();
/*      */     
/* 1405 */     JSONArray arr = new JSONArray();
/*      */     
/* 1407 */     DecimalFormat format = new DecimalFormat("0.00");
/*      */     
/* 1409 */     format.setRoundingMode(RoundingMode.DOWN);
/*      */     
/* 1411 */     for (int i = 0; i < categoryList.size(); i++) {
/*      */       
/* 1413 */       QueryWrapper queryWrapper = new QueryWrapper();
/* 1414 */       queryWrapper.eq("merchant", merchant);
/* 1415 */       queryWrapper.ne("state", "不回收");
/* 1416 */       queryWrapper.orderByDesc("sort");
/* 1417 */       queryWrapper.last("limit " + total);
/*      */       
/* 1419 */       Category category = categoryList.get(i);
/*      */       
/* 1421 */       JSONObject item = (JSONObject)JSON.toJSON(category);
/*      */       
/* 1423 */       item.remove("notes");
/* 1424 */       item.remove("purchase");
/*      */       
/* 1426 */       queryWrapper.eq("cid", category.getId());
/*      */       
/* 1428 */       List<Project> list = this.projectService.list((Wrapper)queryWrapper);
/*      */       
/* 1430 */       JSONArray array = (JSONArray)JSON.toJSON(list);
/*      */       
/* 1432 */       for (int j = 0; j < array.size(); j++) {
/*      */         
/* 1434 */         JSONObject o = array.getJSONObject(j);
/*      */         
/* 1436 */         Double n_points = Double.valueOf(o.getDouble("points").doubleValue() * gain);
/*      */         
/* 1438 */         String str = format.format(n_points);
/*      */         
/* 1440 */         o.put("points", str);
/*      */       } 
/*      */       
/* 1443 */       item.put("item", array);
/*      */       
/* 1445 */       arr.add(item);
/*      */     } 
/*      */ 
/*      */     
/* 1449 */     return R.success(arr);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @GetMapping({"/poster_list"})
/*      */   public R poster_list(String merchant) {
/* 1459 */     List<Poster> list = this.posterService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", Integer.valueOf(1)));
/* 1460 */     return R.success(list);
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"/invitation_member"})
/*      */   public R invitation_member(Long mid, Integer partner, Integer size, Integer pageIndex) {
/* 1470 */     List<MemberDTO> list = this.memberService.getInvitationMember(mid, partner, pageIndex, size);
/*      */     
/* 1472 */     List<MemberDTO> memberCount = this.memberService.getInvitationMemberCount(mid, partner);
/*      */     
/* 1474 */     JSONArray arr = (JSONArray)JSON.toJSON(list);
/*      */     
/* 1476 */     for (int i = 0; i < arr.size(); i++) {
/*      */       
/* 1478 */       JSONObject t = arr.getJSONObject(i);
/*      */       
/* 1480 */       Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", t.getInteger("partner")));
/*      */       
/* 1482 */       t.put("grade_name", grade.getName());
/*      */     } 
/*      */     
/* 1485 */     JSONObject data = new JSONObject();
/*      */     
/* 1487 */     data.put("total", Integer.valueOf(memberCount.size()));
/* 1488 */     data.put("list", arr);
/*      */     
/* 1490 */     return R.success(data);
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
/*      */   
/*      */   @GetMapping({"/query_configuration"})
/*      */   public R queryConfiguration() {
/* 1511 */     Configure configure = (Configure)this.configureService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1514 */     ExtractConfig extractConfig = (ExtractConfig)this.extractConfigService.getOne((Wrapper)new QueryWrapper());
/*      */ 
/*      */     
/* 1517 */     JSONObject configureData = (JSONObject)JSON.toJSON(configure);
/*      */ 
/*      */     
/* 1520 */     OfficialConfig officialConfig = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*      */     
/* 1522 */     configureData.put("officialName", officialConfig.getOfficialName());
/*      */     
/* 1524 */     configureData.put("officialImage", officialConfig.getOfficialImage());
/*      */     
/* 1526 */     JSONObject data = new JSONObject();
/*      */     
/* 1528 */     data.put("config", configureData);
/*      */     
/* 1530 */     data.put("extract", extractConfig);
/*      */     
/* 1532 */     return R.success(data);
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
/*      */   @RequestMapping({"deposit"})
/*      */   public R deposit(String uid) {
/* 1546 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/* 1547 */     queryWrapper.select(new String[] { "IFNULL(sum(points),0) as points" });
/* 1548 */     queryWrapper.eq("uid", uid);
/* 1549 */     queryWrapper.eq("state", "已通过");
/* 1550 */     Map<String, Object> map = this.recordService.getMap((Wrapper)queryWrapper);
/*      */     
/* 1552 */     Double points = (Double)map.get("points");
/*      */ 
/*      */ 
/*      */     
/* 1556 */     Deposit deposit = (Deposit)this.depositService.getOne((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).orderByDesc("create_time")).last("limit 1"));
/*      */     
/* 1558 */     if (deposit == null) {
/* 1559 */       deposit = new Deposit();
/* 1560 */       deposit.setMoney(new BigDecimal("0.0"));
/* 1561 */       deposit.setState(Boolean.valueOf(false));
/*      */     } 
/*      */     
/* 1564 */     JSONObject data = new JSONObject();
/*      */     
/* 1566 */     data.put("points", points);
/*      */     
/* 1568 */     data.put("deposit", deposit);
/*      */ 
/*      */     
/* 1571 */     return R.success(data);
/*      */   }
/*      */ 
/*      */ 
/*      */   
/*      */   @PostMapping({"deposit_withdrawal"})
/*      */   public R deposit_withdrawal(String uid) {
/* 1578 */     List<Member> list = this.memberService.list((Wrapper)(new QueryWrapper()).ne("partner", Integer.valueOf(1)));
/*      */ 
/*      */ 
/*      */     
/* 1582 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*      */     
/* 1584 */     if (member == null) {
/* 1585 */       return R.fail("用户不存在");
/*      */     }
/*      */     
/* 1588 */     QueryWrapper<Record> queryWrapper = new QueryWrapper();
/* 1589 */     queryWrapper.select(new String[] { "IFNULL(sum(points),0) as points" });
/* 1590 */     queryWrapper.eq("uid", uid);
/* 1591 */     queryWrapper.eq("state", "已通过");
/* 1592 */     Map<String, Object> map = this.recordService.getMap((Wrapper)queryWrapper);
/*      */     
/* 1594 */     Double points = (Double)map.get("points");
/*      */     
/* 1596 */     if (points.doubleValue() < 10000.0D) {
/* 1597 */       return R.fail("未满足条件");
/*      */     }
/*      */ 
/*      */     
/* 1601 */     Deposit deposit = (Deposit)this.depositService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("state", Integer.valueOf(0)));
/*      */     
/* 1603 */     if (deposit == null) {
/* 1604 */       return R.fail("押金已提现或不存在");
/*      */     }
/*      */ 
/*      */     
/* 1608 */     Calendar cal = Calendar.getInstance();
/*      */     
/* 1610 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*      */     
/* 1612 */     DateFormat oidTime = new SimpleDateFormat("yyyyMMddHHmmss");
/*      */     
/* 1614 */     Random random = new Random();
/*      */     
/* 1616 */     int i = random.nextInt(1000) + 1000;
/*      */     
/* 1618 */     String oid = oidTime.format(cal.getTime()) + i;
/*      */     
/* 1620 */     Withdrawal withdrawal = new Withdrawal();
/* 1621 */     withdrawal.setId(Integer.valueOf(0));
/* 1622 */     withdrawal.setOid(oid);
/* 1623 */     withdrawal.setMerchant(member.getMerchant());
/* 1624 */     withdrawal.setUid(Integer.valueOf(member.getUid()));
/* 1625 */     withdrawal.setPoints(Double.valueOf(deposit.getMoney().doubleValue()));
/* 1626 */     withdrawal.setChargeMoney(Double.valueOf(0.0D));
/* 1627 */     withdrawal.setRealMoney(Double.valueOf(deposit.getMoney().doubleValue()));
/* 1628 */     withdrawal.setBalance(member.getPoints());
/* 1629 */     withdrawal.setPaymentCode(member.getWxPay());
/* 1630 */     withdrawal.setAlipayName(member.getAlipayName());
/* 1631 */     withdrawal.setAlipayAccount(member.getAlipayAccount());
/* 1632 */     withdrawal.setState("待处理");
/* 1633 */     withdrawal.setCreateTime(stateTime.format(cal.getTime()));
/*      */     
/* 1635 */     boolean save = this.withdrawalService.save(withdrawal);
/*      */ 
/*      */     
/* 1638 */     deposit.setState(Boolean.valueOf(true));
/*      */     
/* 1640 */     this.depositService.saveOrUpdate(deposit);
/*      */ 
/*      */     
/* 1643 */     return R.success(Boolean.valueOf(save));
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
/*      */   @PostMapping({"/cancel_account"})
/*      */   public R cancel_account(Long uid, String phone, String verification_code, HttpSession session) {
/* 1660 */     String code = (String)session.getAttribute("code");
/*      */     
/* 1662 */     System.out.println("验证码：" + code);
/*      */     
/* 1664 */     if (!code.equals(verification_code)) {
/* 1665 */       return R.fail("验证码错误");
/*      */     }
/*      */     
/* 1668 */     Member member = (Member)this.memberService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("uid", uid)).eq("phone", phone));
/*      */     
/* 1670 */     if (member == null) {
/* 1671 */       return R.fail("用户不存在");
/*      */     }
/*      */ 
/*      */ 
/*      */     
/* 1676 */     member.setState("已注销");
/*      */     
/* 1678 */     boolean saveOrUpdate = this.memberService.saveOrUpdate(member);
/*      */     
/* 1680 */     return R.success(Boolean.valueOf(saveOrUpdate));
/*      */   }
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */@GetMapping({"/getConfigure"})
public R getConfigure(
        @RequestParam(value = "version", required = false, defaultValue = "0") String version,
        @RequestParam(value = "brand", required = false) String brand,
        @RequestParam(value = "merchant", required = false) String merchant
) {
    Configure configure;
    if (merchant != null && !"".equals(merchant)) {
        configure = (Configure) this.configureService.getOne(new QueryWrapper<Configure>().eq("merchant", merchant));
    } else {
        configure = (Configure) this.configureService.getOne(new QueryWrapper<>());
    }

    if (configure == null) {
        System.out.println("【LOG】getConfigure: 未找到配置，merchant=" + merchant);
        JSONObject data = new JSONObject();
        // 关键兼容：老版本直接返回空对象，新版本返回{config:{}}
        if (brand == null || brand.trim().isEmpty()) {
            return R.success(new JSONObject());
        } else {
            data.put("config", new JSONObject());
            return R.success(data);
        }
    }

    Integer examine = configure.getExamine();
    String brands = configure.getBrands();
    String configVersion = configure.getVersion() == null ? null : configure.getVersion().toString();

    System.out.println("【LOG】getConfigure: examine=" + examine + ", configVersion=" + configVersion + ", requestVersion=" + version + ", brands=" + brands + ", brand=" + brand);

    int examineResult = 1; // 默认全部不隐藏

    // 兼容老版本：brand为空时，直接examine=1
    if (brand == null || brand.trim().isEmpty()) {
        System.out.println("【LOG】getConfigure: 未传brand，兼容老版本，examineResult=1");
        examineResult = 1;
    } else if (examine != null && examine == 0
            && configVersion != null && configVersion.equals(version)
            && brands != null && !brands.trim().isEmpty()
            && brand != null && !brand.trim().isEmpty()) {
        List<String> brandList = Arrays.stream(brands.split(","))
                .map(String::trim)
                .map(String::toLowerCase)
                .collect(Collectors.toList());
        System.out.println("【LOG】getConfigure: brandList=" + brandList);
        if (brandList.contains(brand.trim().toLowerCase())) {
            examineResult = 0; // 三条件都满足，隐藏
            System.out.println("【LOG】getConfigure: examineResult=0，已命中隐藏条件");
        } else {
            System.out.println("【LOG】getConfigure: brand未命中，examineResult=1");
        }
    } else {
        System.out.println("【LOG】getConfigure: examine/version/brands/brand有一未命中，examineResult=1");
    }

    JSONObject configureData = (JSONObject) JSON.toJSON(configure);
    configureData.put("examine", examineResult);

    OfficialConfig officialConfig = (OfficialConfig) this.officialConfigService.getOne(new QueryWrapper<>());
    if (officialConfig != null) {
        configureData.put("officialName", officialConfig.getOfficialName());
        configureData.put("officialImage", officialConfig.getOfficialImage());
    }

    // === 关键：根据brand参数返回不同结构 ===
    if (brand == null || brand.trim().isEmpty()) {
        // 老版本APP直接返回配置对象（examine固定为1）
        return R.success(configureData);
    } else {
        // 新版本APP返回{config: {...}}
        JSONObject data = new JSONObject();
        data.put("config", configureData);
        return R.success(data);
    }
}
/*      */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ApiController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */