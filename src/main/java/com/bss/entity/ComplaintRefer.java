/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("complaint_refer")
/*    */ public class ComplaintRefer {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String name;
    private Integer sort;
    private Integer state;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date createTime;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ComplaintRefer)) return false;
        com.bss.entity.ComplaintRefer other = (com.bss.entity.ComplaintRefer) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !(!Objects.equals(this$createTime, other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ComplaintRefer;
    }


    public String toString() {
        return "ComplaintRefer(id=" + getId() + ", name=" + getName() + ", sort=" + getSort() + ", state=" + getState() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 15 */
        return this.id;
        /*    */
    }

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        /* 17 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getSort() {
        /* 19 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public Integer getState() {
        /* 21 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }

    /*    */
    public Date getCreateTime() {
        /* 24 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ComplaintRefer.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */