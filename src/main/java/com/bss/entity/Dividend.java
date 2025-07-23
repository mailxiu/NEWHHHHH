/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("dividend")
/*    */ public class Dividend implements Serializable {
    /*    */   private Integer id;
    /*    */   private String relation;
    /*    */   private Integer requestGrade;
    /*    */   private Integer responseGrade;
    /*    */   private Double spread;
    /*    */   private static final long serialVersionUID = 1L;

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    public void setRelation(String relation) {
        this.relation = relation;
    }

    public void setRequestGrade(Integer requestGrade) {
        this.requestGrade = requestGrade;
    }

    public void setResponseGrade(Integer responseGrade) {
        this.responseGrade = responseGrade;
    }

    public void setSpread(Double spread) {
        this.spread = spread;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Dividend)) return false;
        com.bss.entity.Dividend other = (com.bss.entity.Dividend) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$relation = getRelation(), other$relation = other.getRelation();
        if (!Objects.equals(this$relation, other$relation)) return false;
        Object this$requestGrade = getRequestGrade(), other$requestGrade = other.getRequestGrade();
        if (!Objects.equals(this$requestGrade, other$requestGrade))
            return false;
        Object this$responseGrade = getResponseGrade(), other$responseGrade = other.getResponseGrade();
        if (!Objects.equals(this$responseGrade, other$responseGrade))
            return false;
        Object this$spread = getSpread(), other$spread = other.getSpread();
        return !(!Objects.equals(this$spread, other$spread));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Dividend;
    }


    public String toString() {
        return "Dividend(id=" + getId() + ", relation=" + getRelation() + ", requestGrade=" + getRequestGrade() + ", responseGrade=" + getResponseGrade() + ", spread=" + getSpread() + ")";
    }

    /*    */
    public Integer getId() {
        /* 16 */
        return this.id;
        /*    */
    }

    public String getRelation() {
        /* 18 */
        return this.relation;
        /*    */
    }

    public Integer getRequestGrade() {
        /* 20 */
        return this.requestGrade;
        /*    */
    }

    public Integer getResponseGrade() {
        /* 22 */
        return this.responseGrade;
        /*    */
    }

    public Double getSpread() {
        /* 24 */
        return this.spread;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Dividend.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */