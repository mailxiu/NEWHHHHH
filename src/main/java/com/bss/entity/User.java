/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
/*    */ import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("user")
/*    */ public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private String username;
    /*    */   private String password;
    /*    */   private String name;
    private String pattern;
    private String design;
    private String appid;
    private Integer state;
    private String createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.User)) return false;
        com.bss.entity.User other = (com.bss.entity.User) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$username = getUsername(), other$username = other.getUsername();
        if (!Objects.equals(this$username, other$username)) return false;
        Object this$password = getPassword(), other$password = other.getPassword();
        if (!Objects.equals(this$password, other$password)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$pattern = getPattern(), other$pattern = other.getPattern();
        if (!Objects.equals(this$pattern, other$pattern)) return false;
        Object this$design = getDesign(), other$design = other.getDesign();
        if (!Objects.equals(this$design, other$design)) return false;
        Object this$appid = getAppid(), other$appid = other.getAppid();
        if (!Objects.equals(this$appid, other$appid)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.User;
    }


    public String toString() {
        return "User(id=" + getId() + ", merchant=" + getMerchant() + ", username=" + getUsername() + ", password=" + getPassword() + ", name=" + getName() + ", pattern=" + getPattern() + ", design=" + getDesign() + ", appid=" + getAppid() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 19 */
        return this.id;
        /*    */
    }

    /*    */
    /* 16 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 21 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getUsername() {
        /* 23 */
        return this.username;
        /*    */
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        /* 25 */
        return this.password;
        /*    */
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        /* 27 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPattern() {
        /* 29 */
        return this.pattern;
        /*    */
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public String getDesign() {
        /* 31 */
        return this.design;
        /*    */
    }

    public void setDesign(String design) {
        this.design = design;
    }

    public String getAppid() {
        /* 33 */
        return this.appid;
        /*    */
    }

    public void setAppid(String appid) {
        this.appid = appid;
    }

    public Integer getState() {
        /* 35 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public String getCreateTime() {
        /* 37 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\User.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */