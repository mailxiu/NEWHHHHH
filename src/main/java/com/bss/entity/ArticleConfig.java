/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.util.Objects;

/*    */
/*    */
@TableName("article_config")
/*    */ public class ArticleConfig {
    /*    */   private Integer id;
    /*    */   private Integer userArticle;
    /*    */   private Integer privacyArticle;
    /*    */   private Integer cancelArticle;
    private Integer courseArticle;
    private Integer memberArticle;
    private Integer customerArticle;
    private Integer bondArticle;
    private Integer guideArticle;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ArticleConfig)) return false;
        com.bss.entity.ArticleConfig other = (com.bss.entity.ArticleConfig) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$userArticle = getUserArticle(), other$userArticle = other.getUserArticle();
        if (!Objects.equals(this$userArticle, other$userArticle))
            return false;
        Object this$privacyArticle = getPrivacyArticle(), other$privacyArticle = other.getPrivacyArticle();
        if (!Objects.equals(this$privacyArticle, other$privacyArticle))
            return false;
        Object this$cancelArticle = getCancelArticle(), other$cancelArticle = other.getCancelArticle();
        if (!Objects.equals(this$cancelArticle, other$cancelArticle))
            return false;
        Object this$courseArticle = getCourseArticle(), other$courseArticle = other.getCourseArticle();
        if (!Objects.equals(this$courseArticle, other$courseArticle))
            return false;
        Object this$memberArticle = getMemberArticle(), other$memberArticle = other.getMemberArticle();
        if (!Objects.equals(this$memberArticle, other$memberArticle))
            return false;
        Object this$customerArticle = getCustomerArticle(), other$customerArticle = other.getCustomerArticle();
        if (!Objects.equals(this$customerArticle, other$customerArticle))
            return false;
        Object this$bondArticle = getBondArticle(), other$bondArticle = other.getBondArticle();
        if (!Objects.equals(this$bondArticle, other$bondArticle))
            return false;
        Object this$guideArticle = getGuideArticle(), other$guideArticle = other.getGuideArticle();
        return !(!Objects.equals(this$guideArticle, other$guideArticle));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ArticleConfig;
    }


    public String toString() {
        return "ArticleConfig(id=" + getId() + ", userArticle=" + getUserArticle() + ", privacyArticle=" + getPrivacyArticle() + ", cancelArticle=" + getCancelArticle() + ", courseArticle=" + getCourseArticle() + ", memberArticle=" + getMemberArticle() + ", customerArticle=" + getCustomerArticle() + ", bondArticle=" + getBondArticle() + ", guideArticle=" + getGuideArticle() + ")";
    }

    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /*    */
    public void setId(Integer id) {
        /* 13 */
        this.id = id;
    }

    public Integer getUserArticle() {
        /* 17 */
        return this.userArticle;
        /*    */
    }

    public void setUserArticle(Integer userArticle) {
        this.userArticle = userArticle;
    }

    public Integer getPrivacyArticle() {
        /* 19 */
        return this.privacyArticle;
        /*    */
    }

    public void setPrivacyArticle(Integer privacyArticle) {
        this.privacyArticle = privacyArticle;
    }

    public Integer getCancelArticle() {
        /* 21 */
        return this.cancelArticle;
        /*    */
    }

    public void setCancelArticle(Integer cancelArticle) {
        this.cancelArticle = cancelArticle;
    }

    public Integer getCourseArticle() {
        /* 23 */
        return this.courseArticle;
        /*    */
    }

    public void setCourseArticle(Integer courseArticle) {
        this.courseArticle = courseArticle;
    }

    public Integer getMemberArticle() {
        /* 25 */
        return this.memberArticle;
        /*    */
    }

    public void setMemberArticle(Integer memberArticle) {
        this.memberArticle = memberArticle;
    }

    public Integer getCustomerArticle() {
        /* 27 */
        return this.customerArticle;
        /*    */
    }

    public void setCustomerArticle(Integer customerArticle) {
        this.customerArticle = customerArticle;
    }

    public Integer getBondArticle() {
        /* 29 */
        return this.bondArticle;
        /*    */
    }

    public void setBondArticle(Integer bondArticle) {
        this.bondArticle = bondArticle;
    }

    public Integer getGuideArticle() {
        /* 31 */
        return this.guideArticle;
        /*    */
    }

    public void setGuideArticle(Integer guideArticle) {
        this.guideArticle = guideArticle;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ArticleConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */